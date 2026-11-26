//! Explicit fixed-pilot metadata GET. No caller, enrollment or dispatch grant.
use crate::{
    agent_discovery_fetch::{observe_fixed, Status},
    xrpc::App,
};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value as J};
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

pub const METHOD: &str = "chat.atagents.agent.discover";
pub const PATH: &str = "/xrpc/chat.atagents.agent.discover";

#[derive(Clone)]
pub struct Mount {
    permits: Arc<Semaphore>,
}
impl Mount {
    /// Server-owned opt-in only; no caller-selectable DID, URL or authority.
    pub fn fixed() -> Self {
        Self { permits: Arc::new(Semaphore::new(4)) }
    }
    pub(crate) fn validate(&self, origin: &str, audience: &str, dev: bool) -> anyhow::Result<()> {
        let u = reqwest::Url::parse(origin)?;
        let loopback = dev && u.scheme() == "http" && u.host_str() == Some("127.0.0.1") && u.port().is_some();
        anyhow::ensure!(
            u.origin().ascii_serialization() == origin
                && (loopback
                    || origin == crate::agent_endorsement_fetch::PDS && audience == "did:web:pds.crate.social"),
            "Discovery requires reviewed fixed HTTPS origin/audience or dev loopback"
        );
        Ok(())
    }
    pub(crate) fn routes(&self, app: Arc<App>) -> Router {
        Router::new().route(PATH, get(request)).layer(axum::Extension(self.clone())).with_state(app)
    }
}
fn response(status: StatusCode, value: J) -> Response {
    (status, [("cache-control", "no-store")], Json(value)).into_response()
}
async fn request(
    State(_app): State<Arc<App>>,
    axum::Extension(mount): axum::Extension<Mount>,
    req: Request,
) -> Response {
    if req.method() != Method::GET || req.uri().path() != PATH || req.uri().query().is_some() {
        return response(StatusCode::BAD_REQUEST, json!({"error":"InvalidRequest"}));
    }
    // This public-only mount stays outside request decompression. Reject wire
    // encodings/framing before consuming any body or acquiring a resolver slot.
    if req.headers().contains_key("content-encoding")
        || req.headers().contains_key("transfer-encoding")
        || req.headers().get_all("content-length").iter().count() > 1
        || req.headers().get("content-length").is_some_and(|v| v != "0")
    {
        return response(StatusCode::BAD_REQUEST, json!({"error":"EmptyBodyRequired"}));
    }
    // Bound even an unframed slow GET body before any authority request.
    match tokio::time::timeout(Duration::from_secs(1), to_bytes(req.into_body(), 0)).await {
        Ok(Ok(_)) => {}
        _ => return response(StatusCode::BAD_REQUEST, json!({"error":"EmptyBodyRequired"})),
    }
    let Ok(_permit) = mount.permits.clone().try_acquire_owned() else {
        return response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"DiscoveryBusy"}));
    };
    let observation = observe_fixed().await;
    let Ok(at) = observation.observed_at.duration_since(UNIX_EPOCH) else {
        return response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"DiscoveryUnavailable"}));
    };
    match observation.status {
        Status::Advertised(contact) => response(
            StatusCode::OK,
            json!({
                "agentDid":contact.agent,"principalDid":contact.principal,
                "agentCardUrl":contact.card_url,"endpoint":contact.endpoint,
                "contactCommitCid":contact.contact_commit.to_string(),"contactRecordCid":contact.contact_record.to_string(),
                "endorsementCommitCid":contact.endorsement_commit.to_string(),"endorsementRecordCid":contact.endorsement_record.to_string(),
                "observedAt":at.as_secs()
            }),
        ),
        Status::NotAdvertised => response(StatusCode::NOT_FOUND, json!({"error":"NotAdvertised"})),
        Status::Unavailable => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"DiscoveryUnavailable"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_mounted_fixture::common::{Auth, TestServer};
    use crate::{
        agent_a2a::NativeA2a,
        agent_contact_pilot::AGENT_PATH,
        agent_discovery_fetch::tests::{fixture, Mode},
        agent_endorsement_fetch::fixture_transport::{deny_real_https, scope_bytes},
        agent_profile_bridge::Bridge,
    };
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn get(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }
    async fn body(r: Response) -> J {
        assert_eq!(r.headers()["cache-control"], "no-store");
        serde_json::from_slice(&to_bytes(r.into_body(), 4096).await.unwrap()).unwrap()
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn normal_router_defaults_off_and_never_proxies_the_method() {
        let s = TestServer::spawn_lone(|c| {
            c.workers = 1;
            c.shards = 1;
        })
        .await;
        assert!(s.app.config.agent_discovery.is_none());
        let (reply, calls) = fixture(Mode::Valid);
        let r = scope_bytes(
            reply,
            crate::server::public_router(&s.app).oneshot(
                Request::builder()
                    .uri(PATH)
                    .header("atproto-proxy", "did:web:unconfigured.invalid#bsky_appview")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(r.status(), 501);
        assert!(calls.lock().unwrap().is_empty());
        crate::server::shutdown(&s.app).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mounted_discovery_yields_metadata_but_no_caller_authorization() {
        let s = TestServer::spawn_lone(|c| {
            c.workers = 1;
            c.shards = 1;
            c.agent_discovery = Some(Mount::fixed());
            c.agent_a2a = Some(
                NativeA2a::new(
                    &c.public_url,
                    "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                    Bridge::new("http://127.0.0.1:19099", vec![9; 32]).unwrap(),
                    true,
                )
                .unwrap(),
            );
        })
        .await;
        let (reply, calls) = fixture(Mode::Valid);
        let router = crate::server::public_router(&s.app);
        let r = scope_bytes(reply.clone(), router.clone().oneshot(get(PATH))).await.unwrap();
        assert_eq!(r.status(), 200);
        let metadata = body(r).await;
        assert_eq!(metadata["agentDid"], crate::agent_endorsement::AGENT);
        assert_eq!(calls.lock().unwrap().len(), 13);
        for authorization in [None, Some(format!("Bearer {}", metadata))] {
            let mut req = Request::builder()
                .method("POST")
                .uri(AGENT_PATH)
                .header("x-forwarded-user", crate::agent_endorsement::PRINCIPAL);
            if let Some(value) = authorization {
                req = req.header("authorization", value);
            }
            let r = scope_bytes(reply.clone(), router.clone().oneshot(req.body(Body::empty()).unwrap())).await.unwrap();
            assert_eq!(r.status(), 401);
        }
        assert_eq!(calls.lock().unwrap().len(), 13, "Caller denial precedes proof or bridge work");
        crate::server::shutdown(&s.app).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn removals_unavailable_and_bad_requests_are_distinct_without_fallback() {
        let s = TestServer::spawn_lone(|c| {
            c.workers = 1;
            c.shards = 1;
            c.agent_discovery = Some(Mount::fixed());
        })
        .await;
        let router = crate::server::public_router(&s.app);
        for (mode, status, error) in [
            (Mode::ContactAbsent, 404, "NotAdvertised"),
            (Mode::EndorsementAbsent, 404, "NotAdvertised"),
            (Mode::BadCard, 503, "DiscoveryUnavailable"),
            (Mode::RecordUnavailable, 503, "DiscoveryUnavailable"),
        ] {
            let (reply, _) = fixture(mode);
            let r = scope_bytes(reply, router.clone().oneshot(get(PATH))).await.unwrap();
            assert_eq!(r.status(), status);
            assert_eq!(body(r).await["error"], error);
        }
        let (reply, calls) = fixture(Mode::Valid);
        let compressed_empty =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()).finish().unwrap();
        for req in [
            Request::builder().uri(PATH).header("content-encoding", "gzip").body(Body::from(compressed_empty)).unwrap(),
            Request::builder().uri(PATH).header("transfer-encoding", "chunked").body(Body::empty()).unwrap(),
            Request::builder().uri(PATH).header("content-length", "3").body(Body::empty()).unwrap(),
            get(&format!("{PATH}?did=untrusted")),
            Request::builder().uri(PATH).body(Body::from("x")).unwrap(),
            Request::builder()
                .uri(PATH)
                .body(Body::from_stream(futures::stream::pending::<Result<axum::body::Bytes, std::io::Error>>()))
                .unwrap(),
            Request::builder().method("HEAD").uri(PATH).body(Body::empty()).unwrap(),
            Request::builder().method("POST").uri(PATH).body(Body::empty()).unwrap(),
        ] {
            let r = scope_bytes(reply.clone(), router.clone().oneshot(req)).await.unwrap();
            assert!(matches!(r.status().as_u16(), 400 | 405));
        }
        assert!(calls.lock().unwrap().is_empty());
        let r = deny_real_https(router.oneshot(get(PATH))).await.unwrap();
        assert_eq!(r.status(), 503);
        crate::server::shutdown(&s.app).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn global_rate_and_shared_concurrency_limits_precede_resolution() {
        let s = TestServer::spawn_lone(|c| {
            c.workers = 1;
            c.shards = 1;
            c.rate_limits_enabled = true;
            c.agent_discovery = Some(Mount::fixed());
        })
        .await;
        s.xrpc.post("vlpds.admin.updateRateLimits",&json!({"config":{"limiters":{"global-ip":{"points":1,"windowSecs":3600}}},"ifVersion":0,"actor":"synthetic-fixture"}),&Auth::Admin).await.ok();
        let (reply, calls) = fixture(Mode::Valid);
        let router = crate::server::public_router(&s.app);
        for status in [200, 429] {
            let r = scope_bytes(reply.clone(), router.clone().oneshot(get(PATH))).await.unwrap();
            assert_eq!(r.status(), status);
        }
        assert_eq!(calls.lock().unwrap().len(), 13);
        crate::server::shutdown(&s.app).await;
        let s = TestServer::spawn_lone(|c| {
            c.workers = 1;
            c.shards = 1;
            c.agent_discovery = Some(Mount::fixed());
        })
        .await;
        let hold = s.app.config.agent_discovery.as_ref().unwrap().permits.clone().acquire_many_owned(4).await.unwrap();
        let (reply, calls) = fixture(Mode::Valid);
        let r = scope_bytes(reply, crate::server::public_router(&s.app).oneshot(get(PATH))).await.unwrap();
        assert_eq!(r.status(), 503);
        assert_eq!(body(r).await["error"], "DiscoveryBusy");
        assert!(calls.lock().unwrap().is_empty());
        drop(hold);
        crate::server::shutdown(&s.app).await;
    }
    #[test]
    fn production_pins_and_default_configuration_cannot_be_bypassed() {
        let mount = Mount::fixed();
        assert!(crate::server::Config::default().agent_discovery.is_none());
        assert!(mount.validate("https://pds.crate.social", "did:web:pds.crate.social", false).is_ok());
        for (origin, aud, dev) in [
            ("https://other.invalid", "did:web:pds.crate.social", false),
            ("https://pds.crate.social", "did:web:other.invalid", false),
            ("http://127.0.0.1:1234", "did:web:pds.crate.social", false),
            ("http://127.0.0.1:1234/path", "did:web:pds.crate.social", true),
        ] {
            assert!(mount.validate(origin, aud, dev).is_err());
        }
        assert!(mount.validate("http://127.0.0.1:1234", "did:web:fixture.invalid", true).is_ok());
    }
}
