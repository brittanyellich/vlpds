//! Worker-to-PDS dispatch admission. Mounting a transport is a caller decision.

use super::agent_dispatch::{resolve, Binding, Grant};
use super::{App, XResult, XrpcError};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const METHOD: &str = "vlpds.agent.dispatch";
pub const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_LIFETIME_SECS: u64 = 30;

pub struct Authority<'a> {
    pub signer: &'a str,
    pub issuer: &'a str,
    pub resource: &'a str,
}

#[derive(Deserialize)]
struct Assertion {
    iat: u64,
    exp: u64,
    nbf: Option<u64>,
    jti: String,
    issuer: String,
    resource: String,
    owner: String,
    grant: String,
    body_sha256: String,
}

/// Check the exact request bytes before admitting a tool operation. The
/// caller must pass server-configured authority values and mount only POST
/// on the dedicated method path.
pub async fn admit(app: &App, authority: &Authority<'_>, token: &str, body: &[u8]) -> XResult<Binding> {
    let refused = || XrpcError::auth("Dispatch assertion refused");
    if body.len() > MAX_BODY_BYTES {
        return Err(refused());
    }
    let claims = super::authn::verify_dispatch_jwt(app, token, authority.signer, METHOD).await?;
    let claims: Assertion = serde_json::from_value(claims).map_err(|_| refused())?;
    let now = vlatproto::tid::now_micros() / 1_000_000;
    if claims.iat > now.saturating_add(5)
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.exp > claims.iat.saturating_add(MAX_LIFETIME_SECS)
        || claims.nbf.is_some_and(|nbf| nbf > now)
        || claims.jti.len() != 32
        || !claims.jti.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || claims.issuer != authority.issuer
        || claims.resource != authority.resource
        || !vlatproto::syntax::valid_did(&claims.owner)
        || claims.body_sha256 != hex::encode(Sha256::digest(body))
    {
        return Err(refused());
    }
    // An assertion authorizes one attempt, including denial. A retry needs
    // a fresh assertion so a previously refused request cannot become usable.
    let replay_key = format!("agent-dispatch-assertion:{}:{}", authority.signer, claims.jti);
    if !super::internal::claim_replay_anywhere(app, &claims.owner, &replay_key, claims.exp as i64).await? {
        return Err(refused());
    }
    let grant = Grant { issuer: &claims.issuer, resource: &claims.resource, id: &claims.grant, owner: &claims.owner };
    let binding = resolve(app, grant).await.ok_or_else(refused)?;
    if claims.exp <= vlatproto::tid::now_micros() / 1_000_000 {
        return Err(refused());
    }
    Ok(binding)
}
