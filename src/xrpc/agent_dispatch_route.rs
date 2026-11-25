//! Opt-in HTTP transport for a signed MCP dispatch consumer.

use super::agent_dispatch::Binding;
use super::agent_dispatch_auth::{admit, Authority, MAX_BODY_BYTES, METHOD};
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

type Handler = dyn Fn(Binding, Bytes) -> BoxFuture<'static, Response> + Send + Sync;

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
            dispatch: Arc::new(move |binding, body| Box::pin(dispatch(binding, body))),
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
    let Ok(binding) = admit(&app, &authority, token, &body).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let mut response = (mount.dispatch)(binding, body).await;
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
