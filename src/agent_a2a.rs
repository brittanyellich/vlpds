//! Default-off native fixed-agent A2A. Caller authorization, durable decisions,
//! native relationship proof and private profile provenance remain separate.
use crate::agent_contact_pilot::{AGENT_PATH, CARD_PATH};
use crate::{
    agent_a2a_store::{self, Reservation},
    agent_endorsement::{AGENT, PRINCIPAL},
    agent_profile_bridge::Bridge,
    xrpc::App,
};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};

/// The test-only convenience helper stays unavailable in normal builds.
/// Production admission uses the separate explicit default-off opt-in.
/// ```compile_fail
/// use vlpds::agent_a2a::NativeA2a;
/// fn no_fixture_gate(config: NativeA2a) {
///     let _ = config.with_local_enrollment_gate_for_fixture();
/// }
/// ```
#[derive(Clone)]
pub struct NativeA2a {
    origin: String,
    caller: String,
    bridge: Bridge,
    capacity: u32,
    signed_card: Option<crate::agent_card::SignedCard>,
    require_owner_consent: bool,
    #[cfg(test)]
    development: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    enabled: bool,
    caller_did: String,
    #[serde(default)]
    require_owner_consent: bool,
    bridge_origin: String,
    bridge_key_file: String,
    #[serde(default = "default_capacity")]
    decision_capacity: u32,
    signed_card_file: Option<String>,
    card_key_multibase: Option<String>,
}
fn default_capacity() -> u32 {
    1000
}
fn owner_file(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let m = f.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(m.permissions().mode() & 0o077 == 0, "A2A config/key file must be owner-only");
    }
    anyhow::ensure!(m.is_file() && m.len() <= limit, "A2A file limit");
    use std::io::Read;
    let mut b = Vec::new();
    f.take(limit + 1).read_to_end(&mut b)?;
    anyhow::ensure!(b.len() as u64 <= limit, "A2A file limit");
    Ok(b)
}
impl NativeA2a {
    pub fn load(path: &Path, origin: &str, dev: bool) -> anyhow::Result<Self> {
        let c: FileConfig = serde_json::from_slice(&owner_file(path, 4096)?)?;
        anyhow::ensure!(c.enabled, "A2A config requires explicit enabled true");
        let raw = owner_file(Path::new(&c.bridge_key_file), 65)?;
        let key = hex::decode(std::str::from_utf8(&raw)?.trim())?;
        let mut native = Self::new(origin, &c.caller_did, Bridge::new(&c.bridge_origin, key)?, dev)?;
        anyhow::ensure!((1..=100000).contains(&c.decision_capacity), "Decision capacity must be 1..100000");
        native.signed_card = match (c.signed_card_file, c.card_key_multibase) {
            (Some(path), Some(pin)) => Some(
                crate::agent_card::SignedCard::new(serde_json::from_slice(&owner_file(Path::new(&path), 8192)?)?, pin)
                    .map_err(anyhow::Error::msg)?,
            ),
            (None, None) if dev => None,
            _ => anyhow::bail!("Production A2A requires signed_card_file and independent card_key_multibase"),
        };
        native.capacity = c.decision_capacity;
        native.require_owner_consent = c.require_owner_consent;
        Ok(native)
    }
    pub fn new(origin: &str, caller: &str, bridge: Bridge, dev: bool) -> anyhow::Result<Self> {
        let u = reqwest::Url::parse(origin)?;
        anyhow::ensure!(
            u.origin().ascii_serialization() == origin
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
                && (u.scheme() == "https" || dev && u.scheme() == "http" && u.host_str() == Some("127.0.0.1")),
            "A2A requires exact public HTTPS origin"
        );
        anyhow::ensure!(
            vlatproto::syntax::valid_did(caller) && !caller.contains('#') && caller != AGENT,
            "One explicit caller DID required"
        );
        Ok(Self {
            origin: origin.into(),
            caller: caller.into(),
            bridge,
            capacity: default_capacity(),
            signed_card: None,
            require_owner_consent: false,
            #[cfg(test)]
            development: dev,
        })
    }
    /// Test-only loopback convenience helper; delegates to the same admission policy.
    #[cfg(test)]
    pub(crate) fn with_local_enrollment_gate_for_fixture(self) -> anyhow::Result<Self> {
        let origin = reqwest::Url::parse(&self.origin)?;
        anyhow::ensure!(
            self.development && origin.scheme() == "http" && origin.host_str() == Some("127.0.0.1"),
            "Enrollment integration is loopback-only"
        );
        Ok(self.with_owner_consent())
    }
    /// Explicit server-side opt-in. Defaults remain unchanged; this does not grant consent.
    pub fn with_owner_consent(mut self) -> Self {
        self.require_owner_consent = true;
        self
    }
    /// Derive HTTP consent trust pins from the same fixed pair and configured caller.
    /// The CLI mounts this only when the owner-only config explicitly opts in.
    pub fn owner_consent_transport(&self) -> anyhow::Result<Option<crate::agent_enrollment::OwnerConsentTransport>> {
        if !self.require_owner_consent {
            return Ok(None);
        }
        crate::agent_enrollment::OwnerConsentTransport::new(PRINCIPAL.into(), vec![(AGENT.into(), self.caller.clone())])
            .map(Some)
            .map_err(|error| anyhow::anyhow!(error.message))
    }
    pub(crate) fn validate_owner_consent(
        &self,
        transport: Option<&crate::agent_enrollment::OwnerConsentTransport>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.require_owner_consent || transport.is_none(),
            "Native A2A with a consent transport must require owner consent"
        );
        anyhow::ensure!(
            !self.require_owner_consent || transport.is_some_and(|t| t.matches(PRINCIPAL, AGENT, &self.caller)),
            "Owner consent admission requires matching server-owned consent transport pins"
        );
        Ok(())
    }
    pub fn validate(&self, dev: bool, origin: &str) -> anyhow::Result<()> {
        anyhow::ensure!(self.origin == origin, "A2A public origin mismatch");
        anyhow::ensure!(dev || self.signed_card.is_some(), "Production signed Card gate is not configured");
        let url = reqwest::Url::parse(origin)?;
        anyhow::ensure!(
            url.scheme() == "https" || dev && url.scheme() == "http" && url.host_str() == Some("127.0.0.1"),
            "A2A production requires HTTPS even for programmatic configuration"
        );
        Ok(())
    }
    async fn checked_card(&self, app: &App) -> Result<J, String> {
        match &self.signed_card {
            Some(card) => card.checked(app, &self.origin).await,
            None if app.config.dev_mode => Ok(crate::agent_card::template(&self.origin, &app.jwt.service_did)),
            None => Err("Production signed Card required".into()),
        }
    }
    pub fn routes(&self, app: Arc<App>) -> Router {
        let limiter = app.ratelimit.clone();
        let enabled = app.config.rate_limits_enabled;
        let router = Router::new()
            .route(CARD_PATH, get(card))
            .route(AGENT_PATH, post(contact))
            .with_state((app, Arc::new(self.clone())));
        if enabled {
            router.layer(axum::middleware::from_fn_with_state(limiter, crate::ratelimit::layer))
        } else {
            router.layer(axum::middleware::from_fn(crate::ratelimit::unlimited))
        }
    }
}
fn response(status: StatusCode, value: J) -> Response {
    let mut response = (status, [("cache-control", "no-store"), ("a2a-version", "1.0")], Json(value)).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert("www-authenticate", axum::http::HeaderValue::from_static("Bearer"));
    }
    response
}
fn rpc_error(status: StatusCode, id: &J, message: &str) -> Response {
    response(status, json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":message}}))
}
async fn card(State((app, cfg)): State<(Arc<App>, Arc<NativeA2a>)>, req: Request) -> Response {
    if req.uri().path() != CARD_PATH || req.uri().query().is_some() {
        return response(StatusCode::NOT_FOUND, json!({"error":"Not found"}));
    }
    if !app.account(AGENT).await.is_ok_and(|a| a.status.is_none()) {
        return response(StatusCode::NOT_FOUND, json!({"error":"Agent unavailable"}));
    }
    match cfg.checked_card(&app).await {
        Ok(value) => response(StatusCode::OK, value),
        Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"Signed Card trust unavailable"})),
    }
}
fn parse(rpc: &J) -> Result<(J, String, String), i32> {
    let root = rpc.as_object().ok_or(-32600)?;
    let id = correlation_id(rpc);
    if root.len() != 4 || rpc["jsonrpc"] != "2.0" || !rpc["method"].is_string() || id.is_null() {
        return Err(-32600);
    }
    if rpc["method"] != "SendMessage" {
        return Err(-32601);
    }
    let message = &rpc["params"]["message"];
    let event = message["messageId"]
        .as_str()
        .filter(|s| {
            !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        })
        .ok_or(-32602)?;
    let part = &message["parts"][0];
    if rpc["params"].as_object().is_none_or(|o| o.len() != 1)
        || message.as_object().is_none_or(|o| o.len() != 3)
        || message["role"] != "ROLE_USER"
        || message["parts"].as_array().is_none_or(|a| a.len() != 1)
        || !(part.as_object().is_some_and(|o| o.len() == 1 && o.contains_key("data"))
            || part
                .as_object()
                .is_some_and(|o| o.len() == 2 && o.contains_key("data") && part["mediaType"] == "application/json"))
        || part["data"] != json!({"skillId":"resolve-identity-test","agentDid":AGENT,"principalDid":PRINCIPAL})
    {
        return Err(-32602);
    }
    let canonical = serde_json::to_vec(
        &json!({"messageId":event,"skillId":"resolve-identity-test","agentDid":AGENT,"principalDid":PRINCIPAL}),
    )
    .unwrap();
    Ok((id.clone(), event.into(), hex::encode(Sha256::digest(canonical))))
}
fn correlation_id(rpc: &J) -> J {
    let id = &rpc["id"];
    if id.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 128)
        || id.as_i64().is_some_and(|n| (-9007199254740991..=9007199254740991).contains(&n))
    {
        id.clone()
    } else {
        J::Null
    }
}
async fn contact(State((app, cfg)): State<(Arc<App>, Arc<NativeA2a>)>, req: Request) -> Response {
    if req.uri().path() != AGENT_PATH || req.uri().query().is_some() {
        return response(StatusCode::NOT_FOUND, json!({"error":"Not found"}));
    }
    if req.headers().get_all("authorization").iter().count() != 1 {
        return response(StatusCode::UNAUTHORIZED, json!({"error":"Service authentication required"}));
    }
    let Some(token) =
        req.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|s| s.strip_prefix("Bearer "))
    else {
        return response(StatusCode::UNAUTHORIZED, json!({"error":"Service authentication required"}));
    };
    let token = token.to_owned();
    let auth = match crate::xrpc::authn::verify_agent_contact_jwt(&app, &token, &cfg.caller).await {
        Ok(a) => a,
        Err(_) => return response(StatusCode::UNAUTHORIZED, json!({"error":"Caller authentication refused"})),
    };
    let supported_version = req.headers().get_all("a2a-version").iter().count() == 1
        && req.headers().get("a2a-version").and_then(|v| v.to_str().ok()) == Some("1.0");
    if req.headers().get_all("content-type").iter().count() != 1
        || req.headers().contains_key("content-encoding")
        || req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
            != Some("application/json".into())
    {
        return response(StatusCode::UNSUPPORTED_MEDIA_TYPE, json!({"error":"Unencoded JSON required"}));
    }
    let bytes = match tokio::time::timeout(Duration::from_secs(5), to_bytes(req.into_body(), 4096)).await {
        Ok(Ok(b)) => b,
        _ => return response(StatusCode::PAYLOAD_TOO_LARGE, json!({"error":"Request body limit or deadline"})),
    };
    let rpc: J = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(_) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid JSON"}}),
            )
        }
    };
    if !supported_version {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"jsonrpc":"2.0","id":correlation_id(&rpc),"error":{"code":-32009,"message":"A2A version not supported","data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"VERSION_NOT_SUPPORTED","domain":"a2a-protocol.org"}]}}),
        );
    }
    let (id, event, digest) = match parse(&rpc) {
        Ok(v) => v,
        Err(code) => {
            return response(
                StatusCode::BAD_REQUEST,
                json!({"jsonrpc":"2.0","id":correlation_id(&rpc),"error":{"code":code,"message":"Invalid or unsupported fixed request"}}),
            )
        }
    };
    if cfg.require_owner_consent {
        let correlation = id.clone();
        let decision_app = app.clone();
        let decision_cfg = cfg.clone();
        return match crate::agent_admission::run_if_admitted(&app, &token, &cfg.caller, move || {
            contact_decision(decision_app, decision_cfg, auth, id, event, digest)
        })
        .await
        {
            Ok(reply) => reply,
            Err(crate::agent_admission::Refusal::Caller) => {
                rpc_error(StatusCode::UNAUTHORIZED, &correlation, "Caller authentication refused")
            }
            Err(crate::agent_admission::Refusal::Consent) => {
                rpc_error(StatusCode::FORBIDDEN, &correlation, "Owner enrollment consent required")
            }
            Err(_) => {
                rpc_error(StatusCode::SERVICE_UNAVAILABLE, &correlation, "Current enrollment evidence unavailable")
            }
        };
    }
    contact_decision(app, cfg, auth, id, event, digest).await
}
async fn contact_decision(
    app: Arc<App>,
    cfg: Arc<NativeA2a>,
    auth: crate::xrpc::authn::ServiceAuth,
    id: J,
    event: String,
    digest: String,
) -> Response {
    if !app.account(AGENT).await.is_ok_and(|a| a.status.is_none()) {
        return response(StatusCode::NOT_FOUND, json!({"error":"Agent unavailable"}));
    }
    if cfg.checked_card(&app).await.is_err() {
        return rpc_error(StatusCode::SERVICE_UNAVAILABLE, &id, "Signed Card trust unavailable");
    }
    let reserved = match agent_a2a_store::reserve(&app, AGENT, &auth.iss, &event, &digest, cfg.capacity).await {
        Ok(r) => r,
        Err(_) => return rpc_error(StatusCode::SERVICE_UNAVAILABLE, &id, "Durable decision unavailable"),
    };
    let (row, pending) = match reserved {
        Reservation::Cached(mut reply) => {
            reply["id"] = id;
            return response(StatusCode::OK, reply);
        }
        Reservation::Fresh { row, pending } => (row, pending),
        Reservation::Pending | Reservation::Conflict => {
            return rpc_error(StatusCode::CONFLICT, &id, "Prior decision unresolved or request conflict; no redispatch")
        }
        Reservation::Full => {
            return rpc_error(
                StatusCode::TOO_MANY_REQUESTS,
                &id,
                "DecisionCapacityReached: operator capacity increase required; preserve prior decisions",
            )
        }
        Reservation::Busy => return rpc_error(StatusCode::SERVICE_UNAVAILABLE, &id, "Agent busy"),
    };
    let output = async {
        let proof = crate::agent_endorsement_fetch::resolve_fixed().await?;
        let evaluated_at = vlatproto::tid::now_micros() / 1_000_000;
        let bridge_id =
            hex::encode(Sha256::digest(serde_json::to_vec(&json!([AGENT, auth.iss, event, digest])).unwrap()));
        cfg.bridge.assert_profile(&bridge_id).await?;
        Ok::<_, String>((proof, evaluated_at))
    }
    .await;
    let reply = match output {
        Ok((proof, evaluated_at)) => {
            json!({"jsonrpc":"2.0","id":id,"result":{"message":{"role":"ROLE_AGENT","messageId":hex::encode(rand::random::<[u8;16]>()),"contextId":hex::encode(rand::random::<[u8;16]>()),"metadata":{"identityEvaluation":{"atUnix":evaluated_at,"commitCid":proof.get("commitCid"),"recordCid":proof.get("recordCid")}},"parts":[{"mediaType":"application/json","data":{"agentDid":AGENT,"principalDid":PRINCIPAL,"status":proof["status"]}}]}}})
        }
        Err(_) => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Identity lookup or profile assertion failed; no automatic redispatch"}})
        }
    };
    if agent_a2a_store::finish(&app, AGENT, &row, pending, &reply).await.is_err() {
        return rpc_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &id,
            "Decision commit unresolved; reconcile without retrying dispatch",
        );
    }
    response(StatusCode::OK, reply)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_consent_file_switch_defaults_off_and_rejects_nonboolean() {
        let mut value = json!({"enabled":true,"caller_did":"did:web:caller.invalid","bridge_origin":"http://127.0.0.1:31001","bridge_key_file":"synthetic-key"});
        assert!(!serde_json::from_value::<FileConfig>(value.clone()).unwrap().require_owner_consent);
        value["require_owner_consent"] = json!(true);
        assert!(serde_json::from_value::<FileConfig>(value.clone()).unwrap().require_owner_consent);
        value["require_owner_consent"] = json!(false);
        assert!(!serde_json::from_value::<FileConfig>(value.clone()).unwrap().require_owner_consent);
        for malformed in [J::Null, json!("true"), json!(1), json!({})] {
            value["require_owner_consent"] = malformed;
            assert!(serde_json::from_value::<FileConfig>(value.clone()).is_err());
        }
        // Exercise the real owner-only file loader, not only serde or the builder.
        let directory =
            std::env::temp_dir().join(format!("consent-config-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = directory.join("synthetic-key");
        let config = directory.join("config.json");
        let write = |path: &Path, bytes: &[u8]| {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).unwrap().write_all(bytes).unwrap();
        };
        write(&key, hex::encode([11u8; 32]).as_bytes());
        value["bridge_key_file"] = json!(key);
        for setting in [None, Some(false), Some(true)] {
            value.as_object_mut().unwrap().remove("require_owner_consent");
            if let Some(enabled) = setting {
                value["require_owner_consent"] = json!(enabled);
            }
            write(&config, &serde_json::to_vec(&value).unwrap());
            let loaded = NativeA2a::load(&config, "http://127.0.0.1:2583", true).unwrap();
            assert_eq!(loaded.require_owner_consent, setting.unwrap_or(false));
            assert_eq!(loaded.owner_consent_transport().unwrap().is_some(), setting.unwrap_or(false));
            assert!(
                NativeA2a::load(&config, "https://pds.example.invalid", false).is_err(),
                "Consent opt-in never bypasses production signed Card requirements"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn fixed_request_semantic_digest_and_input_guards() {
        let mut r = json!({"jsonrpc":"2.0","id":"one","method":"SendMessage","params":{"message":{"messageId":"event","role":"ROLE_USER","parts":[{"data":{"agentDid":AGENT,"principalDid":PRINCIPAL,"skillId":"resolve-identity-test"}}]}}});
        let d = parse(&r).unwrap().2;
        let mut unknown = r.clone();
        unknown["method"] = json!("UnknownMethod");
        assert_eq!(parse(&unknown), Err(-32601));
        assert_eq!(parse(&J::Null), Err(-32600));
        r["id"] = json!("other");
        r["params"]["message"]["parts"][0]["mediaType"] = json!("application/json");
        assert_eq!(parse(&r).unwrap().2, d);
        r["params"]["message"]["parts"][0]["data"]["url"] = json!("https://evil.invalid");
        assert_eq!(parse(&r), Err(-32602));
    }
}
