//! One-time, owner-bound PAR and callback state for preview enrollment.

use super::{credentials, oauth_client::LoopbackOAuth};
use crate::oauth::util::{b64u, b64u_decode, now_secs, random_id};
use crate::secrets::Purpose;
use crate::xrpc::{
    agent_dispatch::{verify_binding, Binding},
    agent_provisioning::active_owner,
    authn::Credentials,
    cas::{Cond, Op},
    App, XResult, XrpcError,
};
use bytes::Bytes;
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
struct Pending {
    binding: Binding,
    client: String,
    redirect: String,
    private_key: String,
    verifier: String,
    state: String,
    expires: i64,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.verifier.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub client_id: String,
    pub request_uri: String,
    pub authorization_url: String,
    pub state: String,
}

fn denied() -> XrpcError {
    XrpcError::bad(
        "PreviewAuthorizationUnavailable",
        "Preview authorization is stale or does not match the owner and Space",
    )
}

fn state_row(binding: &Binding) -> XResult<String> {
    let binding = serde_json::to_vec(binding).map_err(XrpcError::from_err)?;
    Ok(format!("agent-chat-consent/v1/{}", hex::encode(Sha256::digest(binding))))
}

async fn decode(app: &App, owner: &str, row: &str, raw: &Bytes) -> XResult<Pending> {
    let encrypted = std::str::from_utf8(raw).map_err(|_| denied())?;
    let opened = app
        .secrets
        .unwrap(Purpose::SpacesChatCredential, &format!("{owner}/{row}"), encrypted)
        .await
        .map_err(|_| denied())?;
    serde_json::from_slice(&opened.plaintext).map_err(|_| denied())
}

pub fn check_redirect(redirect: &str) -> anyhow::Result<()> {
    let redirect = reqwest::Url::parse(redirect)?;
    anyhow::ensure!(
        redirect.scheme() == "http"
            && redirect.host_str() == Some("127.0.0.1")
            && redirect.port().is_some()
            && redirect.username().is_empty()
            && redirect.password().is_none()
            && redirect.query().is_none()
            && redirect.fragment().is_none(),
        "EXP-711 enrollment requires an explicit loopback callback"
    );
    Ok(())
}

pub async fn start(
    app: &App,
    oauth: &LoopbackOAuth,
    session: &Credentials,
    binding: &Binding,
    redirect: &str,
) -> XResult<Authorization> {
    let owner = active_owner(app, session).await?;
    verify_binding(app, &owner, binding).await?;
    if oauth.origin() != app.public_url {
        return Err(denied());
    }
    let row = state_row(binding)?;
    let previous = app.get_private(&owner, &row).await?;
    if let Some(ref raw) = previous {
        if decode(app, &owner, &row, raw).await?.expires > now_secs() {
            return Err(denied());
        }
    }
    let scope = credentials::requested_scope(binding).ok_or_else(denied)?;
    let client = if let Some(client) = &app.config.preview_oauth_client {
        if redirect != client.redirect() {
            return Err(denied());
        }
        client.id().to_owned()
    } else {
        check_redirect(redirect).map_err(|_| denied())?;
        reqwest::Url::parse_with_params("http://localhost", [("scope", scope.as_str()), ("redirect_uri", redirect)])
            .map_err(|_| denied())?
            .to_string()
    };
    let state = random_id("mcp-", 32);
    let verifier = Zeroizing::new(random_id("", 32));
    let challenge = b64u(Sha256::digest(verifier.as_bytes()));
    let key = SigningKey::generate();
    let request_uri = oauth
        .par(
            &key,
            &[
                ("client_id", &client),
                ("response_type", "code"),
                ("redirect_uri", redirect),
                ("scope", &scope),
                ("state", &state),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await
        .ok_or_else(denied)?;
    let pending = Pending {
        binding: binding.clone(),
        client: client.clone(),
        redirect: redirect.into(),
        private_key: b64u(key.to_bytes()),
        verifier: verifier.to_string(),
        state: state.clone(),
        expires: now_secs() + 120,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&pending).map_err(XrpcError::from_err)?);
    let encrypted = app
        .secrets
        .wrap(Purpose::SpacesChatCredential, &format!("{owner}/{row}"), &bytes)
        .await
        .map_err(|_| denied())?;
    if !app
        .private_cas(&owner, vec![Cond::eq(&row, previous)], vec![Op::put(&row, Some(Bytes::from(encrypted)))])
        .await?
        .applied
    {
        return Err(denied());
    }
    let authorization_url = reqwest::Url::parse_with_params(
        &format!("{}/oauth/authorize", app.public_url),
        [("client_id", &client), ("request_uri", &request_uri)],
    )
    .map_err(|_| denied())?
    .to_string();
    Ok(Authorization { client_id: client, request_uri, authorization_url, state })
}

pub async fn finish(
    app: &App,
    oauth: &LoopbackOAuth,
    session: &Credentials,
    binding: &Binding,
    state: &str,
    issuer: &str,
    code: &str,
) -> XResult<bool> {
    let owner = active_owner(app, session).await?;
    if issuer != app.public_url || oauth.origin() != issuer {
        return Err(denied());
    }
    let row = state_row(binding)?;
    let raw = app.get_private(&owner, &row).await?.ok_or_else(denied)?;
    let pending = decode(app, &owner, &row, &raw).await?;
    if &pending.binding != binding || !crate::auth::ct_eq(pending.state.as_bytes(), state.as_bytes()) {
        return Err(denied());
    }
    // Consume first, including expired state. No second exchange is permitted.
    if !app.private_cas(&owner, vec![Cond::eq(&row, Some(raw))], vec![Op::put(row.clone(), None)]).await?.applied
        || pending.expires <= now_secs()
    {
        return Err(denied());
    }
    verify_binding(app, &owner, binding).await?;
    let key = Zeroizing::new(b64u_decode(&pending.private_key).ok_or_else(denied)?);
    let signing_key = SigningKey::from_slice(&key).map_err(|_| denied())?;
    let tokens = oauth
        .exchange(&signing_key, &pending.client, &pending.redirect, code, &pending.verifier)
        .await
        .ok_or_else(denied)?;
    credentials::enroll(app, session, binding, &pending.client, &key, &tokens.refresh).await
}
