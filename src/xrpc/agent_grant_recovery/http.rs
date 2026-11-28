//! Private consent transport. Mount only on the trusted service listener.

use super::{CleanupTarget, Observation, Recovery, Request};
use crate::xrpc::agent_dispatch::{Binding, Grant};
use crate::xrpc::{authn, App};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const PATH: &str = "/internal/agent-grant-recovery";
pub const OWNER_SESSION_HEADER: &str = "x-vlpds-owner-session";

type BindingLookup = dyn Fn(&str) -> Option<Binding> + Send + Sync;

#[derive(Clone)]
pub struct Mount {
    issuer: String,
    resource: String,
    service_digest: [u8; 32],
    binding: Arc<BindingLookup>,
    enrollment_redirect: Option<String>,
}

impl Mount {
    pub fn new(
        issuer: &str,
        service_token: &str,
        binding: impl Fn(&str) -> Option<Binding> + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(issuer)?;
        anyhow::ensure!(
            url.scheme() == "https" && url.origin().ascii_serialization() == issuer,
            "Grant recovery requires a canonical HTTPS issuer"
        );
        anyhow::ensure!(
            service_token.len() >= 32 && service_token.bytes().all(|byte| byte.is_ascii_graphic()),
            "Invalid grant recovery service token"
        );
        Ok(Self {
            issuer: issuer.into(),
            resource: format!("{issuer}/mcp"),
            service_digest: Sha256::digest(service_token).into(),
            binding: Arc::new(binding),
            enrollment_redirect: None,
        })
    }

    pub fn with_enrollment(mut self, redirect: String) -> anyhow::Result<Self> {
        crate::xrpc::agent_chat::enrollment::check_redirect(&redirect)?;
        self.enrollment_redirect = Some(redirect);
        Ok(self)
    }

    pub fn private_router(&self, app: Arc<App>) -> Router {
        Router::new().route(PATH, post(request)).layer(DefaultBodyLimit::max(16 * 1024)).with_state((app, self.clone()))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Evidence {
    approval: String,
    client_id: String,
    grant_id: String,
    correlation: String,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum Operation {
    Owner,
    EnrollmentStart,
    EnrollmentFinish {
        state: String,
        issuer: String,
        code: String,
    },
    #[serde(rename_all = "camelCase")]
    Begin {
        approval: String,
        client_id: String,
        binding: Binding,
    },
    Approve(Evidence),
    Revoke(Evidence),
    IssuerCleaned(Evidence),
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

async fn request(
    State((app, mount)): State<(Arc<App>, Mount)>,
    uri: Uri,
    headers: HeaderMap,
    Json(operation): Json<Operation>,
) -> Response {
    let denied = || StatusCode::FORBIDDEN.into_response();
    let Some(service) = single_header(&headers, "authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return denied();
    };
    if uri.query().is_some()
        || headers.contains_key(header::ORIGIN)
        || !crate::auth::ct_eq(&Sha256::digest(service), &mount.service_digest)
    {
        return denied();
    }
    let Some(session) = single_header(&headers, OWNER_SESSION_HEADER) else {
        return denied();
    };
    let (parts, _) =
        axum::http::Request::builder().header(header::AUTHORIZATION, session).body(()).unwrap().into_parts();
    let Ok(credentials) = authn::authenticate(&app, &parts).await else {
        return denied();
    };
    let Ok(recovery) = Recovery::for_session(&app, &credentials).await else {
        return denied();
    };
    let mut response = match operation {
        Operation::EnrollmentStart | Operation::EnrollmentFinish { .. } => {
            enroll(&app, &mount, &credentials, recovery.owner(), operation).await
        }
        _ => execute(&mount, &recovery, operation).await,
    };
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn enroll(app: &App, mount: &Mount, session: &authn::Credentials, owner: &str, operation: Operation) -> Response {
    use crate::xrpc::agent_chat::{enrollment, oauth_client::LoopbackOAuth};
    let denied = || StatusCode::FORBIDDEN.into_response();
    let (Some(redirect), Some(binding)) = (&mount.enrollment_redirect, (mount.binding)(owner)) else {
        return denied();
    };
    let Ok(oauth) = LoopbackOAuth::new(&app.public_url) else {
        return denied();
    };
    match operation {
        Operation::EnrollmentStart => match enrollment::start(app, &oauth, session, &binding, redirect).await {
            Ok(started) => Json(started).into_response(),
            Err(_) => denied(),
        },
        Operation::EnrollmentFinish { state, issuer, code } => {
            match enrollment::finish(app, &oauth, session, &binding, &state, &issuer, &code).await {
                Ok(true) => StatusCode::NO_CONTENT.into_response(),
                Ok(false) => StatusCode::CONFLICT.into_response(),
                Err(_) => denied(),
            }
        }
        _ => denied(),
    }
}

async fn execute(mount: &Mount, recovery: &Recovery<'_>, operation: Operation) -> Response {
    let denied = || StatusCode::FORBIDDEN.into_response();
    match operation {
        Operation::Owner => match (mount.binding)(recovery.owner()) {
            Some(binding) => Json(json!({"did": recovery.owner(), "binding": binding})).into_response(),
            None => denied(),
        },
        Operation::Begin { approval, client_id, binding } => {
            if (mount.binding)(recovery.owner()).as_ref() != Some(&binding) {
                return denied();
            }
            let mut request_digest = [0; 32];
            if hex::decode_to_slice(&approval, &mut request_digest).is_err() {
                return denied();
            }
            let request = Request {
                issuer: mount.issuer.clone(),
                resource: mount.resource.clone(),
                client: client_id,
                request_digest,
                binding,
            };
            match recovery.begin_issuance(&approval, request).await {
                Ok(Some(correlation)) => Json(json!({"correlation": correlation})).into_response(),
                Ok(None) => StatusCode::CONFLICT.into_response(),
                Err(_) => denied(),
            }
        }
        operation => {
            let evidence = match &operation {
                Operation::Approve(evidence) | Operation::Revoke(evidence) | Operation::IssuerCleaned(evidence) => {
                    evidence
                }
                _ => unreachable!(),
            };
            let grant = Grant {
                issuer: &mount.issuer,
                resource: &mount.resource,
                id: &evidence.grant_id,
                owner: recovery.owner(),
            };
            let observed = Observation { grant, client: &evidence.client_id, correlation: &evidence.correlation };
            let success = match operation {
                Operation::Approve(_) => matches!(recovery.issued(&evidence.approval, &observed).await, Ok(true)),
                Operation::Revoke(_) => recovery.reconcile_lost_redirect(&evidence.approval, &observed).await.is_ok(),
                Operation::IssuerCleaned(_) => {
                    recovery.acknowledge(&evidence.approval, &evidence.grant_id, CleanupTarget::Issuer).await.is_ok()
                }
                _ => unreachable!(),
            };
            if success {
                StatusCode::NO_CONTENT.into_response()
            } else {
                denied()
            }
        }
    }
}
