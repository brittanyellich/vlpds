//! Internal owner-consent writer. No HTTP endpoint or provisioning operation.
use crate::{
    agent_admission::Consent,
    xrpc::{
        authn::Credentials,
        cas::{Cond, Op},
        internal, App, XResult,
    },
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vlatproto::xrpc::XrpcError;
const ROW: &str = "agent-enrollment/v1/policy";
const MAX_EVENTS: usize = 64;
const MAX_BYTES: usize = 131072;
const SHUTDOWN_RESERVE: usize = 1024;
#[derive(Clone, Debug)]
pub struct Pair<'a> {
    pub agent: &'a str,
    pub caller: &'a str,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Action {
    Enable,
    Disable,
    RevokeEndorsement,
    OwnerDisable,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub request_id: String,
    pub agent: Option<String>,
    pub action: Action,
    pub revision: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub request_id: String,
    pub agent: Option<String>,
    pub action: Action,
    pub revision: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub receipt: Receipt,
    pub replay: bool,
    pub enabled: bool,
    pub owner_disabled: bool,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    caller: String,
    enabled: bool,
    revoked: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    digest: String,
    receipt: Receipt,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    revision: u64,
    agents: BTreeMap<String, Entry>,
    events: BTreeMap<String, Event>,
    shutdown: Option<Event>,
}
fn denied(message: &str) -> XrpcError {
    XrpcError::bad("EnrollmentRefused", message)
}
async fn load(app: &App, owner: &str) -> XResult<(Option<Bytes>, Policy)> {
    let raw = app.get_private(owner, ROW).await?;
    if raw.as_ref().is_some_and(|b| b.len() > MAX_BYTES) {
        return Err(denied("Policy capacity exceeded"));
    }
    let policy =
        raw.as_ref().map(|b| serde_json::from_slice(b)).transpose().map_err(XrpcError::from_err)?.unwrap_or_default();
    Ok((raw, policy))
}
fn decision(policy: &Policy, event: &Event, replay: bool) -> Decision {
    let enabled =
        event.receipt.agent.as_ref().and_then(|a| policy.agents.get(a)).is_some_and(|a| a.enabled && !a.revoked)
            && policy.shutdown.is_none();
    Decision { receipt: event.receipt.clone(), replay, enabled, owner_disabled: policy.shutdown.is_some() }
}
/// `configured_owner` and `allowlist` are server trust pins, never request arguments.
/// Authenticate the bearer through the existing session extractor; an enum or DID is not proof.
pub async fn apply_owner_consent(
    app: &App,
    token: &str,
    configured_owner: &str,
    allowlist: &[Pair<'_>],
    op: &Operation,
) -> XResult<Decision> {
    if token.len() > 8192 || token.is_empty() {
        return Err(XrpcError::auth("Owner session token required"));
    }
    let (parts, _) = axum::http::Request::builder()
        .header("authorization", format!("Bearer {token}"))
        .body(())
        .map_err(|_| XrpcError::auth("Invalid owner token header"))?
        .into_parts();
    let credentials = crate::xrpc::authn::authenticate(app, &parts).await?;
    apply_authenticated(app, &credentials, configured_owner, allowlist, op).await
}
async fn apply_authenticated(
    app: &App,
    credentials: &Credentials,
    configured_owner: &str,
    allowlist: &[Pair<'_>],
    op: &Operation,
) -> XResult<Decision> {
    let Credentials::Session { did } = credentials else {
        return Err(XrpcError::auth("A full owner session is required"));
    };
    if did != configured_owner || internal::account_anywhere(app, did).await?.status.is_some() {
        return Err(XrpcError::auth("Active configured owner required"));
    }
    if op.action != Action::OwnerDisable {
        if allowlist.is_empty()
            || allowlist.len() > 128
            || allowlist.iter().any(|p| {
                !vlatproto::syntax::valid_did(p.agent) || !vlatproto::syntax::valid_did(p.caller) || p.agent == did
            })
        {
            return Err(denied("Invalid server allowlist"));
        }
        let unique: std::collections::HashSet<_> = allowlist.iter().map(|p| p.agent).collect();
        if unique.len() != allowlist.len() {
            return Err(denied("Ambiguous server allowlist"));
        }
    }
    if op.request_id.is_empty()
        || op.request_id.len() > 64
        || !op.request_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(denied("Invalid request identifier"));
    }
    let pair = if op.action == Action::OwnerDisable {
        if op.agent.is_some() {
            return Err(denied("Owner shutoff has no agent"));
        }
        None
    } else {
        Some(
            allowlist
                .iter()
                .find(|p| Some(p.agent) == op.agent.as_deref())
                .ok_or_else(|| denied("Agent is not allowlisted"))?,
        )
    };
    if op.action == Action::Enable && internal::account_anywhere(app, pair.unwrap().agent).await?.status.is_some() {
        return Err(denied("Existing active agent required"));
    }
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&(configured_owner, op, pair.map(|p| p.caller))).map_err(XrpcError::from_err)?,
    ));
    for _ in 0..16 {
        let (prior, mut policy) = load(app, did).await?;
        let prior_event = policy
            .events
            .get(&op.request_id)
            .or_else(|| policy.shutdown.as_ref().filter(|e| e.receipt.request_id == op.request_id));
        if let Some(event) = prior_event {
            if event.digest != digest {
                return Err(denied("Request conflict"));
            }
            return Ok(decision(&policy, event, true));
        }
        if op.revision != policy.revision {
            return Err(denied("Stale policy revision"));
        }
        if op.action != Action::OwnerDisable && policy.events.len() >= MAX_EVENTS {
            return Err(denied("Decision capacity reached; owner shutoff remains available"));
        }
        if op.action == Action::Enable
            && (policy.shutdown.is_some() || policy.agents.get(pair.unwrap().agent).is_some_and(|a| a.revoked))
        {
            return Err(denied("Revoked or shut off; no automatic restoration"));
        }
        if op.action == Action::OwnerDisable && policy.shutdown.is_some() {
            return Err(denied("Owner is already shut off"));
        }
        let revision = policy.revision.checked_add(1).ok_or_else(|| denied("Revision capacity reached"))?;
        let receipt =
            Receipt { request_id: op.request_id.clone(), agent: op.agent.clone(), action: op.action, revision };
        let event = Event { digest: digest.clone(), receipt };
        if let Some(pair) = pair {
            let entry = policy
                .agents
                .entry(pair.agent.into())
                .or_insert_with(|| Entry { caller: pair.caller.into(), ..Default::default() });
            if entry.caller != pair.caller {
                return Err(denied("Caller binding changed"));
            }
            match op.action {
                Action::Enable => entry.enabled = true,
                Action::Disable => entry.enabled = false,
                Action::RevokeEndorsement => {
                    entry.enabled = false;
                    entry.revoked = true;
                }
                Action::OwnerDisable => unreachable!(),
            }
            policy.events.insert(op.request_id.clone(), event.clone());
        } else {
            policy.shutdown = Some(event.clone());
        }
        policy.revision = revision;
        let next = Bytes::from(serde_json::to_vec(&policy).map_err(XrpcError::from_err)?);
        if next.len() > (if op.action == Action::OwnerDisable { MAX_BYTES } else { MAX_BYTES - SHUTDOWN_RESERVE }) {
            return Err(denied("Policy byte capacity reached"));
        }
        if op.action == Action::Enable {
            crate::xrpc::cas::pause_point("agent_enrollment_enable_before_cas", did).await;
        }
        if app.private_cas(did, vec![Cond::eq(ROW, prior)], vec![Op::put(ROW, Some(next))]).await?.applied {
            return Ok(decision(&policy, &event, false));
        }
    }
    Err(denied("Policy contention; reconcile before another operation"))
}
/// Policy read is not consent creation, caller authentication or identity proof.
pub(crate) async fn current(app: &App, owner: &str, agent: &str) -> Option<Consent> {
    if internal::account_anywhere(app, owner).await.ok()?.status.is_some()
        || internal::account_anywhere(app, agent).await.ok()?.status.is_some()
    {
        return None;
    }
    let (_, policy) = load(app, owner).await.ok()?;
    let entry = policy.agents.get(agent)?;
    Some(Consent {
        version: 1,
        principal: owner.into(),
        agent: agent.into(),
        caller: entry.caller.clone(),
        revision: policy.revision,
        consent_granted: true,
        enabled: entry.enabled,
        endorsement_revoked: entry.revoked,
        owner_disabled: policy.shutdown.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserved_shutdown_space_bounds_maximum_receipt() {
        let before = serde_json::to_vec(&Policy::default()).unwrap().len();
        let policy = Policy {
            revision: u64::MAX,
            shutdown: Some(Event {
                digest: "a".repeat(64),
                receipt: Receipt {
                    request_id: "a".repeat(64),
                    agent: None,
                    action: Action::OwnerDisable,
                    revision: u64::MAX,
                },
            }),
            ..Default::default()
        };
        assert!(serde_json::to_vec(&policy).unwrap().len() - before < SHUTDOWN_RESERVE);
    }
}
