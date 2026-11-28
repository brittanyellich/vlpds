//! Enrollment and sealing for preview-only, owner-approved Spaces grants.

use super::{
    rotation::{Grant, Rotation},
    SessionScope,
};
use crate::oauth::{jose, store, util};
use crate::secrets::Purpose;
use crate::xrpc::{
    agent_dispatch::{verify_binding, Binding},
    App, XResult, XrpcError,
};
use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

pub const THREAD: &str = "com.example.mcpchat.thread";
pub const MESSAGE: &str = "com.example.mcpchat.message";

fn denied() -> XrpcError {
    XrpcError::bad("PreviewCredentialUnavailable", "Expected a current owner-approved scoped OAuth grant")
}

pub fn requested_scope(binding: &Binding) -> Option<String> {
    let scope = SessionScope::from_binding(binding.clone())?;
    Some(format!("atproto {}", scope.oauth_scope(THREAD, MESSAGE)))
}

fn subject(owner: &str, binding: &Binding) -> XResult<String> {
    serde_json::to_string(&(owner, &binding.agent, &binding.space)).map_err(XrpcError::from_err)
}

pub async fn seal(app: &App, owner: &str, binding: &Binding, key: &[u8], refresh: &str) -> XResult<Vec<u8>> {
    if key.len() != 32 || refresh.is_empty() {
        return Err(denied());
    }
    let mut payload = Zeroizing::new(key.to_vec());
    payload.extend_from_slice(refresh.as_bytes());
    let envelope = app
        .secrets
        .wrap(Purpose::SpacesChatCredential, &subject(owner, binding)?, &payload)
        .await
        .map_err(|_| denied())?;
    Ok(envelope.into_bytes())
}

pub async fn open(
    app: &App,
    owner: &str,
    binding: &Binding,
    envelope: &[u8],
) -> XResult<(Zeroizing<[u8; 32]>, Zeroizing<String>)> {
    let envelope = std::str::from_utf8(envelope).map_err(|_| denied())?;
    let payload = app
        .secrets
        .unwrap(Purpose::SpacesChatCredential, &subject(owner, binding)?, envelope)
        .await
        .map_err(|_| denied())?
        .plaintext;
    let (key, refresh) = payload.split_at_checked(32).ok_or_else(denied)?;
    let key = Zeroizing::new(<[u8; 32]>::try_from(key).map_err(|_| denied())?);
    let refresh = Zeroizing::new(std::str::from_utf8(refresh).map_err(|_| denied())?.to_owned());
    if refresh.is_empty() {
        return Err(denied());
    }
    Ok((key, refresh))
}

/// Import only an existing, current OAuth grant approved by this owner for
/// the exact configured Space and dedicated client. The caller supplies
/// the binding and expected client from trusted preview configuration.
pub(crate) async fn enroll(
    app: &App,
    owner: &str,
    binding: &Binding,
    client: &str,
    key: &[u8],
    refresh: &str,
) -> XResult<bool> {
    verify_binding(app, owner, binding).await?;
    let expected = requested_scope(binding).ok_or_else(denied)?;
    let parsed = store::parse_refresh_token(refresh).filter(|token| token.did == owner).ok_or_else(denied)?;
    let grant = store::get_session(app, owner, &parsed.session_id).await.map_err(|_| denied())?.ok_or_else(denied)?;
    let signing_key = SigningKey::from_slice(key).map_err(|_| denied())?;
    let jkt = jose::jwk_thumbprint(&jose::key_to_jwk(signing_key.verifying_key())).map_err(|_| denied())?;
    let refresh_key = util::derive_secret(&app.config.jwt_secret, "refresh-token");
    if grant.client_id != client
        || grant.dpop_jkt != jkt
        || parsed.generation != grant.refresh_gen
        || !parsed.authentic(&refresh_key, &grant)
        || !scope_matches(&grant.scope, &expected)
        || !scope_matches(&grant.token_scope, &expected)
    {
        return Err(denied());
    }
    let sealed = seal(app, owner, binding, key, refresh).await?;
    Rotation::new(app, owner, binding)?
        .install(Grant { issuer: app.config.public_url.clone(), client: grant.client_id, id: grant.id }, sealed)
        .await
}

pub(crate) async fn is_enrolled(app: &App, owner: &str, binding: &Binding) -> XResult<bool> {
    verify_binding(app, owner, binding).await?;
    let Some(grant) = Rotation::new(app, owner, binding)?.ready_grant().await? else { return Ok(false) };
    if grant.issuer != app.public_url {
        return Ok(false);
    }
    let expected = requested_scope(binding).ok_or_else(denied)?;
    let session = store::get_session(app, owner, &grant.id).await.map_err(|_| denied())?;
    Ok(session.is_some_and(|session| {
        session.client_id == grant.client
            && scope_matches(&session.scope, &expected)
            && scope_matches(&session.token_scope, &expected)
    }))
}

/// Runtime session opener. An ambiguous issuer response leaves the claim
/// blocked. A usable access token is returned only after durable completion.
pub async fn refresh(
    app: &App,
    scope: &SessionScope,
    client: &super::oauth_client::LoopbackOAuth,
) -> XResult<(Zeroizing<[u8; 32]>, super::oauth_client::Tokens)> {
    let owner = scope.owner();
    let binding = scope.binding();
    if client.origin() != app.public_url {
        return Err(denied());
    }
    let rotation = Rotation::new(app, owner, binding)?;
    let claim = rotation.claim().await?.ok_or_else(denied)?;
    let (key, old_refresh) = open(app, owner, binding, &claim.envelope).await?;
    let signing_key = SigningKey::from_slice(key.as_slice()).map_err(|_| denied())?;
    if claim.grant().issuer != app.public_url {
        return Err(denied());
    }
    let tokens = client.refresh(&signing_key, &claim.grant().client, &old_refresh).await.ok_or_else(denied)?;
    let old = store::parse_refresh_token(&old_refresh).ok_or_else(denied)?;
    let next = store::parse_refresh_token(&tokens.refresh).ok_or_else(denied)?;
    let expected = requested_scope(binding).ok_or_else(denied)?;
    if next.did != owner
        || next.session_id != claim.grant().id
        || old.generation.checked_add(1) != Some(next.generation)
        || !scope_matches(&tokens.scope, &expected)
    {
        return Err(denied());
    }
    let sealed = seal(app, owner, binding, key.as_slice(), &tokens.refresh).await?;
    if !rotation.complete(claim, sealed).await? {
        return Err(denied());
    }
    Ok((key, tokens))
}

fn scope_matches(actual: &str, expected: &str) -> bool {
    actual.split_whitespace().collect::<std::collections::BTreeSet<_>>() == expected.split_whitespace().collect()
}
