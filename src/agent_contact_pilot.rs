//! Explicit local-only mount for the EXP-710 fixed-agent sidecar. No CAR parser,
//! Kody credentials, arbitrary proxy target, or account configuration lives here.
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub const AGENT_PATH: &str = "/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/a2a/v1";
pub const CARD_PATH: &str = "/agents/did%3Aplc%3A6tlvgafuonoighfrtpejff5m/.well-known/agent-card.json";
const LIMIT: usize = 4096;
const AUTH_HEADERS: [&str; 7] = [
    "a2a-version",
    "x-agent-sender",
    "x-agent-key-id",
    "x-agent-audience",
    "x-agent-timestamp",
    "x-agent-nonce",
    "x-agent-signature",
];

#[derive(Clone)]
pub struct Mount {
    backend: String,
    public_origin: String,
    client: reqwest::Client,
}

fn loopback_origin(value: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value)?;
    anyhow::ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some_and(|port| port >= 1024)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.origin().ascii_serialization() == value,
        "agent contact pilot requires an exact http://127.0.0.1:port origin"
    );
    Ok(())
}

impl Mount {
    pub fn new(backend: &str, public_origin: &str, dev_mode: bool) -> anyhow::Result<Self> {
        anyhow::ensure!(dev_mode, "agent contact pilot is dev-mode only");
        loopback_origin(backend)?;
        loopback_origin(public_origin)?;
        anyhow::ensure!(backend != public_origin, "agent contact sidecar and PDS must be distinct listeners");
        Ok(Self {
            backend: backend.into(),
            public_origin: public_origin.into(),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(80))
                .build()?,
        })
    }

    pub fn validate(&self, dev_mode: bool, public_origin: &str) -> anyhow::Result<()> {
        anyhow::ensure!(dev_mode && public_origin == self.public_origin, "agent contact mount configuration mismatch");
        Ok(())
    }

    pub fn validate_listener(&self, listener: SocketAddr) -> anyhow::Result<()> {
        anyhow::ensure!(
            listener.ip() == Ipv4Addr::LOCALHOST && self.public_origin == format!("http://{listener}"),
            "agent contact pilot requires its exact IPv4 loopback PDS listener"
        );
        Ok(())
    }

    pub fn routes(&self) -> Router {
        Router::new().route(CARD_PATH, get(forward)).route(AGENT_PATH, post(forward)).with_state(Arc::new(self.clone()))
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, [("cache-control", "no-store")], Json(json!({"error": message}))).into_response()
}

async fn forward(State(mount): State<Arc<Mount>>, request: Request) -> Response {
    if !request.extensions().get::<ConnectInfo<SocketAddr>>().is_some_and(|peer| peer.0.ip() == Ipv4Addr::LOCALHOST) {
        return error(StatusCode::FORBIDDEN, "Loopback only");
    }
    if request.uri().query().is_some() {
        return error(StatusCode::NOT_FOUND, "Not found");
    }
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    let mut headers = HeaderMap::new();
    if method == Method::POST {
        for name in AUTH_HEADERS {
            let values = request.headers().get_all(name);
            if values.iter().count() != 1 {
                return error(StatusCode::UNAUTHORIZED, "Signed authentication required");
            }
            headers.insert(name, values.iter().next().unwrap().clone());
        }
        if request.headers().get("x-agent-audience").and_then(|v| v.to_str().ok()) != Some(&mount.public_origin) {
            return error(StatusCode::UNAUTHORIZED, "Incorrect signed audience");
        }
        if request.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|v| v.split(';').next())
            != Some(Some("application/json"))
            || request.headers().contains_key("content-encoding")
        {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Unencoded JSON required");
        }
        headers.insert("content-type", axum::http::HeaderValue::from_static("application/json"));
    }
    let bytes = match tokio::time::timeout(Duration::from_secs(5), to_bytes(request.into_body(), LIMIT)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return error(StatusCode::PAYLOAD_TOO_LARGE, "Request too large"),
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "Request body timeout"),
    };
    let mut upstream = match mount
        .client
        .request(method, format!("{}{path}", mount.backend))
        .headers(headers)
        .body(bytes)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return error(StatusCode::BAD_GATEWAY, "Local contact sidecar unavailable"),
    };
    if upstream.status().is_redirection()
        || upstream.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|v| v.split(';').next())
            != Some(Some("application/json"))
        || upstream.content_length().is_some_and(|n| n > LIMIT as u64)
    {
        return error(StatusCode::BAD_GATEWAY, "Invalid local contact response");
    }
    let status = upstream.status();
    let mut body = Vec::new();
    loop {
        match upstream.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= LIMIT => body.extend_from_slice(&chunk),
            Ok(None) => break,
            _ => return error(StatusCode::BAD_GATEWAY, "Invalid local contact response"),
        }
    }
    // The sidecar's configured audience also controls its card endpoint. Verify
    // it here so an accidental default cannot advertise the unmounted backend.
    if path == CARD_PATH {
        let card = serde_json::from_slice::<serde_json::Value>(&body);
        if !card.is_ok_and(|value| {
            value["supportedInterfaces"][0]["url"].as_str()
                == Some(format!("{}{AGENT_PATH}", mount.public_origin).as_str())
        }) {
            return error(StatusCode::BAD_GATEWAY, "Contact card audience mismatch");
        }
    }
    (status, [("content-type", "application/json"), ("cache-control", "no-store")], Body::from(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn opt_in_is_dev_and_exact_loopback_only() {
        let backend = "http://127.0.0.1:32100";
        let origin = "http://127.0.0.1:32101";
        assert!(Mount::new(backend, origin, false).is_err());
        for invalid in [
            "http://localhost:32100",
            "https://127.0.0.1:32100",
            "http://127.0.0.1:32100/path",
            "http://127.0.0.1:32100?target=x",
            "http://user:secret@127.0.0.1:32100",
        ] {
            assert!(Mount::new(invalid, origin, true).is_err());
        }
        assert!(Mount::new(origin, origin, true).is_err());
        let mount = Mount::new(backend, origin, true).unwrap();
        assert!(mount.validate_listener("127.0.0.1:32101".parse().unwrap()).is_ok());
        assert!(mount.validate_listener("0.0.0.0:32101".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn native_mount_rejects_missing_peer_external_peer_and_duplicate_auth() {
        let mount = Mount::new("http://127.0.0.1:32100", "http://127.0.0.1:32101", true).unwrap();
        let missing = axum::http::Request::builder().uri(CARD_PATH).body(Body::empty()).unwrap();
        assert_eq!(mount.routes().oneshot(missing).await.unwrap().status(), StatusCode::FORBIDDEN);
        let remote = axum::http::Request::builder()
            .uri(CARD_PATH)
            .extension(ConnectInfo("192.0.2.1:1234".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();
        assert_eq!(mount.routes().oneshot(remote).await.unwrap().status(), StatusCode::FORBIDDEN);
        let mut duplicate = axum::http::Request::builder()
            .method("POST")
            .uri(AGENT_PATH)
            .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
            .body(Body::empty())
            .unwrap();
        for name in AUTH_HEADERS {
            duplicate.headers_mut().insert(name, axum::http::HeaderValue::from_static("fixture"));
        }
        duplicate.headers_mut().append("x-agent-sender", axum::http::HeaderValue::from_static("duplicate"));
        assert_eq!(mount.routes().oneshot(duplicate).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
