//! Fixed-authority bounded discovery reads. No route mounts this resolver and no
//! result grants caller access. The normal build has no test transport override.
use crate::{
    agent_contact_pilot::CARD_PATH,
    agent_discovery::{discover_fixed, Contact, Evidence, RecordRead, Snapshot},
    agent_endorsement::{TrustedSnapshot, AGENT, MAX_CAR_BYTES, PRINCIPAL},
    agent_endorsement_fetch::{check_pds, document, head_for, read, rpc, PDS},
};
use serde_json::Value as J;
use std::time::{Duration, SystemTime};

const AUDIENCE: &str = "did:web:pds.crate.social";

#[derive(Debug)]
pub enum Status {
    Advertised(Box<Contact>),
    NotAdvertised,
    Unavailable,
}
#[derive(Debug)]
pub struct Observation {
    /// Start time includes every network read; it is not a freshness lease.
    pub observed_at: SystemTime,
    pub status: Status,
}

async fn record(did: &str, collection: &str, rkey: &str) -> Result<Option<J>, String> {
    let (status, bytes) = read(
        rpc("com.atproto.repo.getRecord", &[("repo", did), ("collection", collection), ("rkey", rkey)]),
        4096,
        true,
    )
    .await?;
    let body: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid independent record JSON")?;
    match status {
        200 => Ok(Some(body)),
        400 | 404 if body["error"] == "RecordNotFound" => Ok(None),
        _ => Err("Independent record unavailable".into()),
    }
}
async fn proof(did: &str, collection: &str, rkey: &str) -> Result<Vec<u8>, String> {
    let (status, bytes) = read(
        rpc("com.atproto.sync.getRecord", &[("did", did), ("collection", collection), ("rkey", rkey)]),
        MAX_CAR_BYTES,
        false,
    )
    .await?;
    if status != 200 {
        return Err("Discovery proof unavailable".into());
    }
    Ok(bytes)
}
fn independent(value: &Option<J>) -> RecordRead<'_> {
    match value {
        Some(record) => RecordRead::Found(record),
        None => RecordRead::Absent,
    }
}
async fn resolve_inner() -> Result<Option<Contact>, String> {
    let agent = document(AGENT).await?;
    let principal = document(PRINCIPAL).await?;
    check_pds(&agent)?;
    check_pds(&principal)?;
    let principal_before = head_for(PRINCIPAL).await?;
    let agent_before = head_for(AGENT).await?;
    let endorsement = record(PRINCIPAL, "link.ident.endorsement", AGENT).await?;
    let contact = record(AGENT, "link.ident.agent", "self").await?;
    let endorsement_car = proof(PRINCIPAL, "link.ident.endorsement", AGENT).await?;
    let contact_car = proof(AGENT, "link.ident.agent", "self").await?;
    // Never follow the record URL. Fetch only the reviewed fixed Card path.
    // Signed absence requires no Card, but both repositories are still observed.
    let card = if endorsement.is_some() && contact.is_some() {
        let url = reqwest::Url::parse(&format!("{PDS}{CARD_PATH}")).expect("fixed HTTPS Card URL");
        let (status, bytes) = read(url, 8192, true).await?;
        if status != 200 {
            return Err("Discovery Card unavailable".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "Invalid Card JSON")?
    } else {
        J::Null
    };
    let principal_after = head_for(PRINCIPAL).await?;
    let agent_after = head_for(AGENT).await?;
    // Reread both authorities even after absence; no cached or legacy fallback.
    if document(AGENT).await? != agent || document(PRINCIPAL).await? != principal {
        return Err("Discovery DID authority changed".into());
    }
    if agent_before != agent_after || principal_before != principal_after {
        return Err("Discovery repository changed".into());
    }
    discover_fixed(
        &Snapshot {
            relationship: TrustedSnapshot {
                agent_document: &agent,
                principal_document: &principal,
                head_before: principal_before,
                head_after: principal_after,
            },
            agent_head_before: agent_before,
            agent_head_after: agent_after,
        },
        Evidence {
            endorsement_car: &endorsement_car,
            endorsement_record: independent(&endorsement),
            contact_car: &contact_car,
            contact_record: independent(&contact),
            card: &card,
        },
        PDS,
        AUDIENCE,
    )
}
/// Internal opt-in building block only. No config, CLI, HTTP route or cache is
/// added; existing default-off mounts and caller admission remain unchanged.
pub async fn observe_fixed() -> Observation {
    observe_resolution(resolve_inner(), Duration::from_secs(20)).await
}
async fn observe_resolution(
    resolution: impl std::future::Future<Output = Result<Option<Contact>, String>>,
    deadline: Duration,
) -> Observation {
    let observed_at = SystemTime::now();
    let status = match tokio::time::timeout(deadline, resolution).await {
        Ok(Ok(Some(contact))) => Status::Advertised(Box::new(contact)),
        Ok(Ok(None)) => Status::NotAdvertised,
        _ => Status::Unavailable,
    };
    Observation { observed_at, status }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::agent_discovery::tests::{proof, Fixture};
    use crate::agent_endorsement_fetch::fixture_transport::{deny_real_https, scope_bytes};
    use serde_json::json;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    use vlatproto::cid::Cid;

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Mode {
        Valid,
        ContactAbsent,
        EndorsementAbsent,
        RecordUnavailable,
        WrongUrl,
        BadCard,
        ChangedAgentHead,
        ChangedPrincipalHead,
        ChangedDid,
        WrongMedia,
        Redirect,
        Encoded,
        OversizedHeader,
        InvalidLength,
        OversizedBody,
        MissingProof,
        Tampered,
    }

    pub(crate) fn fixture(
        mode: Mode,
    ) -> (Arc<dyn Fn(&reqwest::Url) -> Result<reqwest::Response, String> + Send + Sync>, Arc<Mutex<Vec<String>>>) {
        let mut f = Fixture::new_at(PDS, AUDIENCE);
        if matches!(mode, Mode::ContactAbsent) {
            f.contact = proof(AGENT, &f.agent_key, "link.ident.agent/self", None);
        }
        if matches!(mode, Mode::EndorsementAbsent) {
            f.endorsement = proof(PRINCIPAL, &f.principal_key, &format!("link.ident.endorsement/{AGENT}"), None);
        }
        if matches!(mode, Mode::WrongUrl) {
            f.contact = proof(
                AGENT,
                &f.agent_key,
                "link.ident.agent/self",
                Some(json!({"$type":"link.ident.agent","agentCardUrl":"https://unconfigured.invalid/card"})),
            );
        }
        if matches!(mode, Mode::BadCard) {
            f.card["name"] = json!("tampered");
        }
        let mut replies: HashMap<String, (u16, &'static str, Vec<u8>)> = HashMap::new();
        for (did, doc) in [(AGENT, &f.agent), (PRINCIPAL, &f.principal)] {
            let mut url = reqwest::Url::parse("https://plc.directory").unwrap();
            url.path_segments_mut().unwrap().push(did);
            replies.insert(url.to_string(), (200, "application/json", serde_json::to_vec(doc).unwrap()));
        }
        for (did, collection, rkey, data) in [
            (AGENT, "link.ident.agent", "self", &f.contact),
            (PRINCIPAL, "link.ident.endorsement", AGENT, &f.endorsement),
        ] {
            replies.insert(
                rpc("com.atproto.sync.getLatestCommit", &[("did", did)]).to_string(),
                (200, "application/json", serde_json::to_vec(&json!({"cid":data.0.to_string()})).unwrap()),
            );
            let (status, body) = match &data.2 {
                Some(record) => (200, serde_json::to_vec(record).unwrap()),
                None => (404, br#"{"error":"RecordNotFound"}"#.to_vec()),
            };
            replies.insert(
                rpc("com.atproto.repo.getRecord", &[("repo", did), ("collection", collection), ("rkey", rkey)])
                    .to_string(),
                (status, "application/json", body),
            );
            replies.insert(
                rpc("com.atproto.sync.getRecord", &[("did", did), ("collection", collection), ("rkey", rkey)])
                    .to_string(),
                (200, "application/vnd.ipld.car", data.1.clone()),
            );
        }
        replies.insert(format!("{PDS}{CARD_PATH}"), (200, "application/json", serde_json::to_vec(&f.card).unwrap()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let captured = calls.clone();
        let counts = Mutex::new(HashMap::<String, usize>::new());
        let reply = Arc::new(move |url: &reqwest::Url| {
            let key = url.to_string();
            captured.lock().unwrap().push(key.clone());
            let mut n = counts.lock().unwrap();
            let count = n.entry(key.clone()).or_default();
            *count += 1;
            let (mut status, mut media, mut bytes) =
                replies.get(&key).cloned().ok_or("Unexpected synthetic request")?;
            if matches!(mode, Mode::ChangedDid)
                && url.origin().ascii_serialization() == "https://plc.directory"
                && *count == 2
            {
                let mut doc: J = serde_json::from_slice(&bytes).unwrap();
                doc["changed"] = json!(true);
                bytes = serde_json::to_vec(&doc).unwrap();
            }
            if url.path() == "/xrpc/com.atproto.sync.getLatestCommit" && *count == 2 {
                let did = url.query_pairs().find(|(k, _)| k == "did").unwrap().1;
                if matches!(mode, Mode::ChangedAgentHead) && did == AGENT
                    || matches!(mode, Mode::ChangedPrincipalHead) && did == PRINCIPAL
                {
                    bytes = serde_json::to_vec(&json!({"cid":Cid::dag_cbor(b"changed").to_string()})).unwrap();
                }
            }
            if url.path() == "/xrpc/com.atproto.repo.getRecord" && matches!(mode, Mode::RecordUnavailable) {
                status = 503;
                bytes = br#"{"error":"RecordNotFound"}"#.to_vec();
            }
            if url.path() == "/xrpc/com.atproto.sync.getRecord" {
                if matches!(mode, Mode::MissingProof) {
                    status = 404;
                }
                if matches!(mode, Mode::Tampered) {
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                }
            }
            if url.path() == CARD_PATH {
                if matches!(mode, Mode::WrongMedia) {
                    media = "text/html";
                }
                if matches!(mode, Mode::Redirect) {
                    status = 302;
                }
                if matches!(mode, Mode::OversizedBody) {
                    bytes.resize(8193, b'x');
                }
            }
            let mut response = axum::http::Response::builder()
                .status(status)
                .header("content-type", media)
                .header("content-encoding", if matches!(mode, Mode::Encoded) { "gzip" } else { "identity" });
            if url.path() == CARD_PATH && matches!(mode, Mode::OversizedHeader) {
                response = response.header("content-length", "8193");
            }
            if url.path() == CARD_PATH && matches!(mode, Mode::InvalidLength) {
                response = response.header("content-length", "invalid");
            }
            Ok(reqwest::Response::from(response.body(reqwest::Body::from(bytes)).unwrap()))
        });
        (reply, calls)
    }
    #[tokio::test]
    async fn complete_fixed_reads_return_verified_public_routing_only() {
        let (reply, calls) = fixture(Mode::Valid);
        let before = SystemTime::now();
        let result = scope_bytes(reply, observe_fixed()).await;
        assert!(result.observed_at >= before);
        let Status::Advertised(contact) = result.status else { panic!("Synthetic current discovery should verify") };
        assert_eq!(contact.agent, AGENT);
        assert_eq!(contact.card_url, format!("{PDS}{CARD_PATH}"));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 13);
        assert!(calls
            .iter()
            .all(|url| url.starts_with("https://plc.directory/") || url.starts_with(&format!("{PDS}/"))));
    }
    #[tokio::test]
    async fn signed_removal_is_not_advertised_without_card_fallback() {
        for mode in [Mode::ContactAbsent, Mode::EndorsementAbsent] {
            let (reply, calls) = fixture(mode);
            assert!(matches!(scope_bytes(reply, observe_fixed()).await.status, Status::NotAdvertised));
            assert!(!calls.lock().unwrap().iter().any(|url| url.ends_with(CARD_PATH)));
        }
    }
    #[tokio::test]
    async fn invalid_or_unavailable_evidence_never_returns_cached_or_alternate_contact() {
        for mode in [
            Mode::RecordUnavailable,
            Mode::WrongUrl,
            Mode::BadCard,
            Mode::ChangedAgentHead,
            Mode::ChangedPrincipalHead,
            Mode::ChangedDid,
            Mode::WrongMedia,
            Mode::Redirect,
            Mode::Encoded,
            Mode::OversizedHeader,
            Mode::InvalidLength,
            Mode::OversizedBody,
            Mode::MissingProof,
            Mode::Tampered,
        ] {
            let (reply, calls) = fixture(mode);
            assert!(matches!(scope_bytes(reply, observe_fixed()).await.status, Status::Unavailable), "{mode:?}");
            assert!(!calls.lock().unwrap().iter().any(|url| url.starts_with("https://unconfigured.invalid")));
        }
    }
    #[tokio::test]
    async fn total_deadline_is_unavailable_without_fallback() {
        let result = observe_resolution(std::future::pending(), Duration::from_millis(10)).await;
        assert!(matches!(result.status, Status::Unavailable));
    }
    #[tokio::test]
    async fn no_fixture_can_escape_to_real_https_and_observation_includes_wait() {
        assert!(matches!(deny_real_https(observe_fixed()).await.status, Status::Unavailable));
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(observe_resolution(
            async move {
                entered.send(()).unwrap();
                wait.await.unwrap();
                Ok(None)
            },
            Duration::from_secs(20),
        ));
        started.await.unwrap();
        let pending = SystemTime::now();
        release.send(()).unwrap();
        assert!(task.await.unwrap().observed_at <= pending);
    }
}
