//! Opt-in HTTP transport for a signed MCP dispatch consumer.

use super::agent_chat::{dispatch_scoped, ScopedSession, SessionScope};
use super::agent_dispatch::Binding;
use super::agent_dispatch_auth::{admit_request, Admission, Authority, MAX_BODY_BYTES, METHOD};
use super::App;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use futures::future::BoxFuture;
use std::future::Future;
use std::sync::Arc;

type Handler = dyn Fn(Arc<App>, Admission, Bytes) -> BoxFuture<'static, Response> + Send + Sync;

#[derive(Clone)]
pub struct Mount {
    signer: String,
    issuer: String,
    resource: String,
    dispatch: Arc<Handler>,
}

impl Mount {
    /// Embed a trusted tool handler with preconfigured authority. The
    /// handler receives the approved binding and the exact signed bytes.
    pub fn new<F, Fut>(signer: &str, issuer: &str, resource: &str, dispatch: F) -> anyhow::Result<Self>
    where
        F: Fn(Binding, Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        Self::with_admission(signer, issuer, resource, move |_, admission, body| dispatch(admission.binding, body))
    }

    fn with_admission<F, Fut>(signer: &str, issuer: &str, resource: &str, dispatch: F) -> anyhow::Result<Self>
    where
        F: Fn(Arc<App>, Admission, Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        anyhow::ensure!(vlatproto::syntax::valid_did(signer), "Invalid MCP dispatch signer DID");
        for value in [issuer, resource] {
            let url = reqwest::Url::parse(value)?;
            anyhow::ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
                    && value.len() <= 2048
                    && !value.chars().any(char::is_control),
                "Invalid MCP dispatch authority URL"
            );
        }
        Ok(Self {
            signer: signer.into(),
            issuer: issuer.into(),
            resource: resource.into(),
            dispatch: Arc::new(move |app, admission, body| Box::pin(dispatch(app, admission, body))),
        })
    }

    /// Open a fresh server-owned chat session only after signed admission.
    /// The provider supplies scoped credentials for this binding from
    /// trusted server state, independently of the MCP request body.
    pub fn chat<S, F, Fut>(signer: &str, issuer: &str, resource: &str, open: F) -> anyhow::Result<Self>
    where
        S: ScopedSession + Send + 'static,
        F: Fn(SessionScope) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<S>> + Send + 'static,
    {
        let open = Arc::new(open);
        Self::with_admission(signer, issuer, resource, move |app, admission, body| {
            let open = open.clone();
            async move { dispatch_scoped(&app, &*open, admission, &body).await }
        })
    }

    pub(crate) fn routes(&self, app: Arc<App>) -> Router {
        Router::new()
            .route(&format!("/xrpc/{METHOD}"), post(request))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state((app, self.clone()))
    }
}

async fn request(State((app, mount)): State<(Arc<App>, Mount)>, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    if uri.query().is_some() || headers.contains_key(header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut auth = headers.get_all(header::AUTHORIZATION).iter();
    let token = auth.next().and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "));
    let Some(token) = token.filter(|_| auth.next().is_none()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let authority = Authority { signer: &mount.signer, issuer: &mount.issuer, resource: &mount.resource };
    let Ok(admission) = admit_request(&app, &authority, token, &body).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let mut response = (mount.dispatch)(app, admission, body).await;
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
