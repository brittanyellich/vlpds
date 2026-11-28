//! Identity-only browser authorization for the isolated preview app.

use super::oauth_client::LoopbackOAuth;
use crate::oauth::{
    store,
    util::{b64u, b64u_decode, now_secs, random_id},
};
use crate::secrets::Purpose;
use crate::xrpc::{internal, App};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const SESSION_SECONDS: i64 = 300;

#[derive(Serialize, Deserialize)]
struct Pending {
    owner: String,
    verifier: String,
    key: String,
    expires: i64,
}

#[derive(Serialize, Deserialize)]
struct AppSession {
    owner: String,
    oauth_session: String,
    expires: i64,
}

fn session_subject(app: &App) -> String {
    format!("exp711-app-session/{}", app.public_url)
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.verifier.zeroize();
        self.key.zeroize();
    }
}

fn subject(app: &App, state: &str) -> String {
    format!("exp711-app-login/{}/{state}", app.public_url)
}

pub(crate) async fn owner_for_handle(app: &App, handle: &str) -> Option<String> {
    let handle = handle.to_ascii_lowercase();
    if !vlatproto::syntax::valid_handle(&handle) {
        return None;
    }
    app.resolve_handle(&handle).await.ok()?
}

pub(crate) async fn start(app: &App, oauth: &LoopbackOAuth, owner: &str) -> Option<Value> {
    let client = app.config.preview_oauth_client.as_ref()?.identity();
    if oauth.origin() != app.public_url || internal::account_anywhere(app, owner).await.ok()?.status.is_some() {
        return None;
    }
    let state = random_id("login-", 32);
    let key = SigningKey::generate();
    let verifier = Zeroizing::new(random_id("", 32));
    let challenge = b64u(Sha256::digest(verifier.as_bytes()));
    let request_uri = oauth
        .par(
            &key,
            &[
                ("client_id", client.id()),
                ("response_type", "code"),
                ("redirect_uri", client.redirect()),
                ("scope", "atproto"),
                ("state", &state),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("login_hint", owner),
            ],
        )
        .await?;
    let pending = Pending {
        owner: owner.into(),
        verifier: verifier.to_string(),
        key: b64u(key.to_bytes()),
        expires: now_secs() + 120,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&pending).ok()?);
    let context = app.secrets.wrap(Purpose::SpacesChatCredential, &subject(app, &state), &bytes).await.ok()?;
    let url = reqwest::Url::parse_with_params(
        &format!("{}/oauth/authorize", app.public_url),
        [("client_id", client.id()), ("request_uri", &request_uri)],
    )
    .ok()?;
    Some(json!({"state": state, "authorizationUrl": url.as_str(), "context": context}))
}

pub(crate) async fn finish(
    app: &App,
    oauth: &LoopbackOAuth,
    issuer: &str,
    state: &str,
    code: &str,
    context: &str,
) -> Option<String> {
    let client = app.config.preview_oauth_client.as_ref()?.identity();
    if issuer != app.public_url || oauth.origin() != issuer {
        return None;
    }
    let raw = app.secrets.unwrap(Purpose::SpacesChatCredential, &subject(app, state), context).await.ok()?;
    let pending: Pending = serde_json::from_slice(&raw.plaintext).ok()?;
    if pending.expires <= now_secs() {
        return None;
    }
    let key = Zeroizing::new(b64u_decode(&pending.key)?);
    let key = SigningKey::from_slice(&key).ok()?;
    let tokens = oauth.exchange(&key, client.id(), client.redirect(), code, &pending.verifier).await?;
    let (did, sid) = crate::xrpc::oauth::preview_identity(app, &tokens.access, client.id(), &key).await?;
    if did != pending.owner || internal::account_anywhere(app, &did).await.ok()?.status.is_some() {
        return None;
    }
    let session = AppSession { owner: did, oauth_session: sid, expires: now_secs() + SESSION_SECONDS };
    let clear = Zeroizing::new(serde_json::to_vec(&session).ok()?);
    app.secrets.wrap(Purpose::SpacesChatCredential, &session_subject(app), &clear).await.ok()
}

pub(crate) async fn verify(app: &App, authorization: &str) -> Option<String> {
    let client = app.config.preview_oauth_client.as_ref()?.identity();
    let token = authorization.strip_prefix("Preview ")?;
    let clear = app.secrets.unwrap(Purpose::SpacesChatCredential, &session_subject(app), token).await.ok()?;
    let claims: AppSession = serde_json::from_slice(&clear.plaintext).ok()?;
    if claims.expires <= now_secs() {
        return None;
    }
    let session = store::get_session(app, &claims.owner, &claims.oauth_session).await.ok()??;
    if session.client_id != client.id()
        || session.scope != "atproto"
        || session.expires_at <= now_secs()
        || internal::account_anywhere(app, &claims.owner).await.ok()?.status.is_some()
    {
        return None;
    }
    Some(claims.owner)
}
