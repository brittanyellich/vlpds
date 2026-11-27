//! Fixed-origin bounded public metadata/proof fetch. No caller URLs or JS parser.
use crate::agent_endorsement::{self, Outcome, TrustedSnapshot, AGENT, MAX_CAR_BYTES, PRINCIPAL};
use crate::xrpc::agent_binding::{PairObservation, PairStatus};
use futures::StreamExt;
use serde_json::{json, Value as J};
use std::time::Duration;
use std::time::SystemTime;
use vlatproto::cid::Cid;

#[cfg(test)]
pub(crate) mod fixture_transport;

const PLC: &str = "https://plc.directory";
pub(crate) const PDS: &str = "https://pds.crate.social";

pub(crate) async fn read(url: reqwest::Url, limit: usize, json_body: bool) -> Result<(u16, Vec<u8>), String> {
    if ![PLC, PDS].contains(&url.origin().ascii_serialization().as_str()) {
        return Err("Unconfigured identity authority".into());
    }
    let response = fetch_response(&url, json_body).await?;
    let status = response.status().as_u16();
    let media = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let declared_length = response
        .headers()
        .get("content-length")
        .map(|v| {
            v.to_str().map_err(|_| "Invalid identity length")?.parse::<u64>().map_err(|_| "Invalid identity length")
        })
        .transpose()?;
    if response.status().is_redirection()
        || declared_length.is_some_and(|n| n > limit as u64)
        || response.content_length().is_some_and(|n| n > limit as u64)
        || response.headers().get("content-encoding").is_some_and(|v| v != "identity")
        || (json_body && !["application/json", "application/did+ld+json"].contains(&media.as_str()))
        || (!json_body && media != "application/vnd.ipld.car")
    {
        return Err("Invalid bounded identity response".into());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "Identity body failed")?;
        if bytes.len() + chunk.len() > limit {
            return Err("Identity body limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}
async fn fetch_response(url: &reqwest::Url, json_body: bool) -> Result<reqwest::Response, String> {
    #[cfg(test)]
    if let Some(fixture) = fixture_transport::current() {
        return tokio::time::timeout(Duration::from_secs(3), fixture.reply(url))
            .await
            .map_err(|_| "Identity fetch failed")?;
    }
    #[cfg(test)]
    if let Some(reply) = fixture_transport::byte_reply(url) {
        return reply;
    }
    #[cfg(test)]
    if fixture_transport::https_denied() {
        return Err("Unscoped fixture identity read refused".into());
    }
    let response = vlatproto::http::guarded(false)
        .get(url.as_str())?
        .header(
            "accept",
            if json_body { "application/json, application/did+ld+json" } else { "application/vnd.ipld.car" },
        )
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .map_err(|_| "Identity fetch failed")?;
    Ok(response)
}

pub(crate) fn rpc(method: &str, params: &[(&str, &str)]) -> reqwest::Url {
    let mut u = reqwest::Url::parse(&format!("{PDS}/xrpc/{method}")).expect("constant URL");
    u.query_pairs_mut().extend_pairs(params.iter().copied());
    u
}
pub(crate) async fn document(did: &str) -> Result<J, String> {
    let mut u = reqwest::Url::parse(PLC).expect("constant URL");
    u.path_segments_mut().unwrap().push(did);
    let (status, bytes) = read(u, 32768, true).await?;
    if status != 200 {
        return Err("DID authority unavailable".into());
    }
    let doc: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid DID JSON")?;
    if doc["id"] != did || doc.get("deactivated").is_some_and(|v| v != &json!(false)) {
        return Err("Invalid active DID".into());
    }
    Ok(doc)
}
pub(crate) fn check_pds(doc: &J) -> Result<(), String> {
    let services = doc["service"].as_array().ok_or("Missing PDS")?;
    if services.len() > 64 {
        return Err("PDS service limit".into());
    }
    let did = doc["id"].as_str().ok_or("Missing DID")?;
    let full = format!("{did}#atproto_pds");
    let mut matches = services.iter().filter(|s| s["id"] == "#atproto_pds" || s["id"] == full);
    let s = matches.next().ok_or("Missing PDS service")?;
    if matches.next().is_some() || s["type"] != "AtprotoPersonalDataServer" || s["serviceEndpoint"] != PDS {
        return Err("PDS migration requires explicit endpoint review".into());
    }
    Ok(())
}
async fn head() -> Result<Cid, String> {
    head_for(PRINCIPAL).await
}
pub(crate) async fn head_for(did: &str) -> Result<Cid, String> {
    if ![AGENT, PRINCIPAL].contains(&did) {
        return Err("Unconfigured repository head".into());
    }
    let (status, bytes) = read(rpc("com.atproto.sync.getLatestCommit", &[("did", did)]), 4096, true).await?;
    if status != 200 {
        return Err("Current head unavailable".into());
    }
    let j: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid head JSON")?;
    Cid::parse(j["cid"].as_str().ok_or("Missing head CID")?).map_err(|_| "Invalid head CID".into())
}
async fn resolve_inner() -> Result<PairStatus, String> {
    let agent = document(AGENT).await?;
    check_pds(&agent)?;
    let aliases: &[J] = match agent.get("alsoKnownAs") {
        None => &[],
        Some(J::Array(a)) => a,
        _ => return Err("Invalid agent aliases".into()),
    };
    if aliases.len() > 128 || !aliases.iter().all(J::is_string) {
        return Err("Invalid agent aliases".into());
    }
    let alias = format!("https://ident.link/agent-of/{PRINCIPAL}");
    if !aliases.iter().any(|v| v == &alias) {
        if document(AGENT).await? != agent {
            return Err("DID metadata changed during observation".into());
        }
        return Ok(PairStatus::Undeclared);
    }
    let principal = document(PRINCIPAL).await?;
    check_pds(&principal)?;
    let before = head().await?;
    let params = [("repo", PRINCIPAL), ("collection", "link.ident.endorsement"), ("rkey", AGENT)];
    let (status, bytes) = read(rpc("com.atproto.repo.getRecord", &params), 4096, true).await?;
    let record: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid record JSON")?;
    let record = match status {
        200 => Some(record),
        400 | 404 if record["error"] == "RecordNotFound" => None,
        _ => return Err("Record lookup failed".into()),
    };
    let (status, car) = read(
        rpc(
            "com.atproto.sync.getRecord",
            &[("did", PRINCIPAL), ("collection", "link.ident.endorsement"), ("rkey", AGENT)],
        ),
        MAX_CAR_BYTES,
        false,
    )
    .await?;
    if status != 200 {
        return Err("Record proof unavailable".into());
    }
    let after = head().await?;
    // Catch observed key/declaration changes across the proof snapshot. This
    // still trusts HTTPS authorities and cannot prove no later/ABA mutation.
    if document(AGENT).await? != agent || document(PRINCIPAL).await? != principal {
        return Err("DID metadata changed during proof".into());
    }
    let snapshot = TrustedSnapshot {
        agent_document: &agent,
        principal_document: &principal,
        head_before: before,
        head_after: after,
    };
    match agent_endorsement::verify(&snapshot, &car, record.as_ref())? {
        Outcome::Verified { commit, record } => Ok(PairStatus::Verified { commit, record }),
        Outcome::Absent { commit } => Ok(PairStatus::SignedAbsent { commit }),
    }
}
async fn resolve_bounded() -> Result<PairStatus, String> {
    tokio::time::timeout(Duration::from_secs(20), resolve_inner()).await.map_err(|_| "Identity resolution deadline")?
}
/// Typed sibling for internal admission only; same fixed HTTPS authority/pair pins.
/// Test transport is absent from the normal library API:
/// ```compile_fail
/// use vlpds::agent_endorsement_fetch::fixture_transport;
/// ```
/// Resolution start bounds the oldest evidence age; this is not a global freshness lease.
pub async fn observe_fixed() -> PairObservation {
    observe_resolution(resolve_bounded()).await
}
async fn observe_resolution(
    resolution: impl std::future::Future<Output = Result<PairStatus, String>>,
) -> PairObservation {
    let observed_at = SystemTime::now();
    let status = resolution.await.unwrap_or(PairStatus::Unavailable);
    PairObservation { agent: AGENT.into(), principal: PRINCIPAL.into(), observed_at, status }
}
/// Preserve the legacy fixed identity evaluation JSON and error behavior.
pub async fn resolve_fixed() -> Result<J, String> {
    legacy_status(resolve_bounded().await?)
}
fn legacy_status(status: PairStatus) -> Result<J, String> {
    Ok(match status {
        PairStatus::Verified { commit, record } => {
            json!({"agentDid":AGENT,"principalDid":PRINCIPAL,"status":"verified","commitCid":commit.to_string(),"recordCid":record.to_string()})
        }
        PairStatus::SignedAbsent { commit } => {
            json!({"agentDid":AGENT,"principalDid":PRINCIPAL,"status":"declared_unverified","commitCid":commit.to_string()})
        }
        PairStatus::Undeclared => json!({"agentDid":AGENT,"principalDid":PRINCIPAL,"status":"no_declaration"}),
        PairStatus::Unavailable => return Err("Identity observation unavailable".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn observation_age_includes_resolution_delay() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(observe_resolution(async move {
            started_tx.send(()).unwrap();
            release_rx.await.unwrap();
            Ok(PairStatus::Undeclared)
        }));
        started_rx.await.unwrap();
        let pending_at = SystemTime::now();
        release_tx.send(()).unwrap();
        let observation = task.await.unwrap();
        assert!(observation.observed_at <= pending_at);
        assert!(matches!(observation.status, PairStatus::Undeclared));
    }
    #[test]
    fn typed_observation_preserves_legacy_outcomes() {
        let commit = Cid::dag_cbor(b"synthetic-commit");
        let record = Cid::dag_cbor(b"synthetic-record");
        assert_eq!(legacy_status(PairStatus::Verified { commit, record }).unwrap()["status"], "verified");
        assert_eq!(legacy_status(PairStatus::SignedAbsent { commit }).unwrap()["status"], "declared_unverified");
        assert_eq!(legacy_status(PairStatus::Undeclared).unwrap()["status"], "no_declaration");
        assert!(legacy_status(PairStatus::Unavailable).is_err());
    }
    #[test]
    fn fixed_urls_and_service_migration_gate() {
        let u = rpc("com.atproto.sync.getRecord", &[("did", PRINCIPAL), ("rkey", AGENT)]);
        assert_eq!(u.origin().ascii_serialization(), PDS);
        assert_eq!(u.query_pairs().find(|(k, _)| k == "rkey").unwrap().1, AGENT);
        let mut d = json!({"id":PRINCIPAL,"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":PDS}]});
        assert!(check_pds(&d).is_ok());
        d["service"][0]["serviceEndpoint"] = json!("https://unconfigured.invalid");
        assert!(check_pds(&d).is_err());
    }
}

#[cfg(test)]
mod live_check {
    #[tokio::test]
    #[ignore = "Explicit read-only public HTTPS interoperability check; no credentials or writes"]
    async fn fixed_public_proof_read_only() {
        let result = super::resolve_fixed().await.expect("bounded native public proof");
        assert_eq!(result["status"], "verified");
        println!("{}", serde_json::to_string(&result).unwrap());
    }
}

/// Fixed authoritative public Card document. Explicit absence/deactivation is
/// distinct from transport/protocol failure; only the former retires a pin.
pub(crate) async fn card_document() -> Result<Option<J>, String> {
    let mut url = reqwest::Url::parse(PLC).expect("constant URL");
    url.path_segments_mut().unwrap().push(AGENT);
    let (status, bytes) = read(url, 32768, true).await?;
    if matches!(status, 404 | 410) {
        return Ok(None);
    }
    if status != 200 {
        return Err("Card DID authority unavailable".into());
    }
    let doc: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid Card DID JSON")?;
    if doc["id"] != AGENT {
        return Err("Wrong Card DID".into());
    }
    Ok(Some(doc))
}
