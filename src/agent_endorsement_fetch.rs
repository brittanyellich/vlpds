//! Fixed-origin bounded public metadata/proof fetch. No caller URLs or JS parser.
use crate::agent_endorsement::{self, Outcome, TrustedSnapshot, AGENT, MAX_CAR_BYTES, PRINCIPAL};
use futures::StreamExt;
use serde_json::{json, Value as J};
use std::time::Duration;
use vlatproto::cid::Cid;

const PLC: &str = "https://plc.directory";
const PDS: &str = "https://pds.crate.social";

async fn read(url: reqwest::Url, limit: usize, json_body: bool) -> Result<(u16, Vec<u8>), String> {
    if ![PLC, PDS].contains(&url.origin().ascii_serialization().as_str()) {
        return Err("Unconfigured identity authority".into());
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
    if response.status().is_redirection()
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
fn rpc(method: &str, params: &[(&str, &str)]) -> reqwest::Url {
    let mut u = reqwest::Url::parse(&format!("{PDS}/xrpc/{method}")).expect("constant URL");
    u.query_pairs_mut().extend_pairs(params.iter().copied());
    u
}
async fn document(did: &str) -> Result<J, String> {
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
fn check_pds(doc: &J) -> Result<(), String> {
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
    let (status, bytes) = read(rpc("com.atproto.sync.getLatestCommit", &[("did", PRINCIPAL)]), 4096, true).await?;
    if status != 200 {
        return Err("Current head unavailable".into());
    }
    let j: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid head JSON")?;
    Cid::parse(j["cid"].as_str().ok_or("Missing head CID")?).map_err(|_| "Invalid head CID".into())
}
async fn resolve_inner() -> Result<J, String> {
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
        return Ok(json!({"agentDid":AGENT,"principalDid":PRINCIPAL,"status":"no_declaration"}));
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
        Outcome::Verified { commit, record } => Ok(
            json!({"agentDid":AGENT,"principalDid":PRINCIPAL,"status":"verified","commitCid":commit.to_string(),"recordCid":record.to_string()}),
        ),
        Outcome::Absent { commit } => Ok(
            json!({"agentDid":AGENT,"principalDid":PRINCIPAL,"status":"declared_unverified","commitCid":commit.to_string()}),
        ),
    }
}
/// Only this fixed pair and these fixed HTTPS authorities. No runtime parameters.
pub async fn resolve_fixed() -> Result<J, String> {
    tokio::time::timeout(Duration::from_secs(20), resolve_inner()).await.map_err(|_| "Identity resolution deadline")?
}

#[cfg(test)]
mod tests {
    use super::*;
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
