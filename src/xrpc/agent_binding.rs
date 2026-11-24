//! Current ident.link evidence from the configured PLC directory and this
//! PDS's hosted principal repo. Public proof conveys no private consent.

use super::{App, XResult, XrpcError};
use crate::agent_endorsement::{verify_pair, Outcome, TrustedSnapshot};
use crate::plc::format_did_doc;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};
use vlatproto::cid::Cid;

#[derive(Debug, PartialEq, Eq)]
pub enum PairStatus {
    Verified {
        commit: Cid,
        record: Cid,
    },
    SignedAbsent {
        commit: Cid,
    },
    Undeclared,
    /// A snapshot, identity, or signed proof could not be established.
    Unavailable,
}

#[derive(Debug)]
pub struct PairObservation {
    pub agent: String,
    pub principal: String,
    /// Local time after finishing the observation. This is not a freshness lease.
    pub observed_at: SystemTime,
    pub status: PairStatus,
}

/// Bind the observation to an expected pair. This function does not consult
/// provisioning state, accept caller-supplied evidence, or grant access.
pub async fn observe(app: &App, agent: &str, principal: &str) -> PairObservation {
    let status = tokio::time::timeout(Duration::from_secs(3), read_pair(app, agent, principal))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(PairStatus::Unavailable);
    PairObservation { agent: agent.into(), principal: principal.into(), observed_at: SystemTime::now(), status }
}

async fn read_pair(app: &App, agent: &str, principal: &str) -> XResult<PairStatus> {
    let Some(plc) = &app.plc else {
        return Ok(PairStatus::Unavailable);
    };
    if agent == principal || !vlatproto::plc::valid_plc_did(agent) || !vlatproto::plc::valid_plc_did(principal) {
        return Ok(PairStatus::Unavailable);
    }
    super::sync::assert_available(app, principal, None).await?;
    let path = format!("link.ident.endorsement/{agent}");
    if super::admin::is_record_takendown(app, principal, &path).await? {
        return Ok(PairStatus::Unavailable);
    }

    let head_before = app.head(principal).await?.commit;
    let (principal_data, agent_data) =
        tokio::try_join!(plc.client.document_data(principal), plc.client.document_data(agent))?;
    if [(&principal_data, principal), (&agent_data, agent)]
        .into_iter()
        .any(|(data, did)| data["did"] != did || data.get("deactivated").is_some_and(|value| value != false))
    {
        return Ok(PairStatus::Unavailable);
    }
    let principal_document = format_did_doc(&principal_data);
    let agent_document = format_did_doc(&agent_data);
    let aliases = match agent_data.get("alsoKnownAs") {
        None => &[][..],
        Some(Value::Array(aliases)) if aliases.len() <= 128 && aliases.iter().all(Value::is_string) => {
            aliases.as_slice()
        }
        _ => return Ok(PairStatus::Unavailable),
    };
    let declaration = format!("https://ident.link/agent-of/{principal}");
    let evidence = if aliases.iter().any(|alias| alias == &declaration) {
        let record = current_record(app, principal, &path).await?;
        let car = super::sync::record_proof(app, principal, &path).await?;
        Some((record, car))
    } else {
        None
    };
    super::cas::pause_point("agent_binding_before_final_snapshot", principal).await;
    let (principal_after, agent_after) =
        tokio::try_join!(plc.client.document_data(principal), plc.client.document_data(agent))?;
    super::sync::assert_available(app, principal, None).await?;
    if super::admin::is_record_takendown(app, principal, &path).await? {
        return Ok(PairStatus::Unavailable);
    }
    let head_after = app.head(principal).await?.commit;
    if principal_data != principal_after || agent_data != agent_after || head_before != head_after {
        return Ok(PairStatus::Unavailable);
    }
    let Some((record, car)) = evidence else {
        return Ok(PairStatus::Undeclared);
    };
    let snapshot = TrustedSnapshot {
        principal_document: &principal_document,
        agent_document: &agent_document,
        head_before,
        head_after,
    };
    Ok(match verify_pair(agent, principal, &snapshot, &car, record.as_ref()) {
        Ok(Outcome::Verified { commit, record }) => PairStatus::Verified { commit, record },
        Ok(Outcome::Absent { commit }) => PairStatus::SignedAbsent { commit },
        Err(_) => PairStatus::Unavailable,
    })
}

async fn current_record(app: &App, principal: &str, path: &str) -> XResult<Option<Value>> {
    let Some(raw) = app.record_value(principal, None, path).await? else {
        return Ok(None);
    };
    let (cid, bytes) = crate::state::decode_record_value(&raw).map_err(XrpcError::from_err)?;
    if bytes.len() > 4096 {
        return Err(XrpcError::bad("EndorsementTooLarge", "Endorsement was too large to verify"));
    }
    let value = vlatproto::cbor::Value::decode(&bytes).map_err(XrpcError::from_err)?.to_json();
    Ok(Some(json!({"uri": format!("at://{principal}/{path}"), "cid": cid.to_string(), "value": value})))
}
