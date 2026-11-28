//! Durable mapping for a separately authenticated MCP grant. This module does
//! not verify bearer tokens or expose a network endpoint.

use super::agent_provisioning::{active_owner, binding_is_verified};
use super::authn::Credentials;
use super::cas::{Cond, Op};
use super::{App, XResult, XrpcError};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Internal grant identity from trusted issuer integration. At dispatch the
/// caller must first validate the token, its issuer, audience, and scope.
/// `id` is stable across access/refresh rotation and unique within this issuer
/// and resource. Obtain `owner` from the verified grant, never tool arguments.
#[derive(Clone, Copy)]
pub struct Grant<'a> {
    pub issuer: &'a str,
    pub resource: &'a str,
    pub id: &'a str,
    pub owner: &'a str,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Binding {
    pub agent: String,
    // Stored grants from earlier alphas retain their identity on read. New
    // approvals are still checked strictly by verify_binding.
    #[serde(deserialize_with = "crate::state::stored_uri::deserialize")]
    pub space: String,
}

#[derive(Deserialize, PartialEq, Eq, Serialize)]
pub(super) enum Row {
    Approved(Binding),
    Revoked,
}

impl Grant<'_> {
    pub(super) fn row(self) -> XResult<String> {
        let fields = [self.issuer, self.resource, self.id];
        if fields.into_iter().any(|field| field.is_empty() || field.len() > 2048 || field.chars().any(char::is_control))
            || !vlatproto::syntax::valid_did(self.owner)
        {
            return Err(XrpcError::bad("InvalidDispatchGrant", "Invalid MCP grant identity"));
        }
        // Length is bounded above and control characters (including NUL)
        // were refused, so the three encoded fields cannot alias one another.
        let digest = Sha256::digest(fields.join("\0"));
        Ok(format!("agent-dispatch/v1/{}", hex::encode(digest)))
    }
}

pub(super) fn encode(row: &Row) -> XResult<Bytes> {
    let mut value = serde_json::to_value(row).map_err(XrpcError::from_err)?;
    if let Row::Approved(binding) = row {
        value["Approved"]["space"] =
            serde_json::Value::String(crate::state::stored_space_uri(&binding.space).into_owned());
    }
    serde_json::to_vec(&value).map(Bytes::from).map_err(XrpcError::from_err)
}

async fn verify_owner(app: &App, owner_session: &Credentials, grant: Grant<'_>) -> XResult<()> {
    if active_owner(app, owner_session).await? != grant.owner {
        return Err(XrpcError::auth("Grant owner does not match the signed-in account"));
    }
    Ok(())
}

pub(super) async fn verify_binding(app: &App, owner: &str, binding: &Binding) -> XResult<()> {
    if !vlatproto::syntax::parse_space_uri(&binding.space)
        .is_some_and(|uri| uri.authority == owner && uri.record.is_none())
    {
        return Err(XrpcError::bad("InvalidDispatchSpace", "Expected a Space governed by the owner"));
    }
    if !binding_is_verified(app, owner, &binding.agent).await {
        return Err(XrpcError::bad("AgentBindingUnavailable", "Verified owner-agent binding is unavailable"));
    }

    Ok(())
}

/// Record owner consent for an immutable pair and Space. Repeat approval of
/// the same mapping is idempotent. A revoked grant ID cannot be reused.
pub async fn approve(app: &App, owner_session: &Credentials, grant: Grant<'_>, binding: Binding) -> XResult<()> {
    verify_owner(app, owner_session, grant).await?;
    let row = grant.row()?;
    verify_binding(app, grant.owner, &binding).await?;

    let bytes = encode(&Row::Approved(binding))?;
    let written =
        app.private_cas(grant.owner, vec![Cond::eq(&row, None)], vec![Op::put(&row, Some(bytes.clone()))]).await?;
    if written.applied || app.get_private(grant.owner, &row).await?.as_ref() == Some(&bytes) {
        return Ok(());
    }
    Err(XrpcError::bad("DispatchGrantUnavailable", "MCP grant already has a different binding or was revoked"))
}

/// Revoke at the owner partition, even if approval has not landed yet.
/// The tombstone fences both retried and concurrent approval.
pub async fn revoke(app: &App, owner_session: &Credentials, grant: Grant<'_>) -> XResult<()> {
    verify_owner(app, owner_session, grant).await?;
    let row = grant.row()?;
    app.private_cas(grant.owner, vec![], vec![Op::put(row, Some(encode(&Row::Revoked)?))]).await?;
    Ok(())
}

/// Resolve only while the owner, binding, and original grant mapping are
/// current. Failure or unavailable evidence denies dispatch. Revocation can
/// still race work after the last observation of the binding or grant row.
pub async fn resolve(app: &App, grant: Grant<'_>) -> Option<Binding> {
    let row = grant.row().ok()?;
    let before = app.get_private(grant.owner, &row).await.ok()??;
    let Row::Approved(binding) = serde_json::from_slice(&before).ok()? else {
        return None;
    };
    if !binding_is_verified(app, grant.owner, &binding.agent).await {
        return None;
    }
    super::cas::pause_point("agent_dispatch_before_final_read", grant.owner).await;
    if !binding_is_verified(app, grant.owner, &binding.agent).await {
        return None;
    }
    let after = app.get_private(grant.owner, &row).await.ok()??;
    (before == after).then_some(binding)
}

#[cfg(test)]
mod nov24_tests {
    use super::*;

    #[test]
    fn legacy_grant_storage_normalizes_without_rewriting_identity() {
        let old = br#"{"Approved":{"agent":"did:plc:agent","space":"at://did:plc:owner/space/com.example.chat/main"}}"#;
        let row: Row = serde_json::from_slice(old).unwrap();
        let Row::Approved(binding) = &row else { panic!("approved fixture") };
        assert_eq!(binding.space, "at:space/did:plc:owner/com.example.chat/main");
        assert_eq!(encode(&row).unwrap_or_else(|e| panic!("{}", e.message)).as_ref(), old);
        // Public representations remain canonical; only the durable row
        // encoder preserves the legacy storage representation.
        assert_eq!(serde_json::to_value(binding).unwrap()["space"], binding.space);
    }
}
