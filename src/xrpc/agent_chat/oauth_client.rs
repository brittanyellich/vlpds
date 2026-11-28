//! Server-owned OAuth transport for the isolated, loopback PDS issuer.

use crate::oauth::{jose, util};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use reqwest::{Client, Method, Url};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use zeroize::Zeroizing;

pub struct LoopbackOAuth {
    http: Client,
    endpoint: Url,
}

pub struct Tokens {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub scope: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    scope: String,
}

impl LoopbackOAuth {
    pub fn new(origin: &str) -> anyhow::Result<Self> {
        Self::with_listener(origin, origin)
    }

    /// Connect an HTTP loopback issuer through its current private listener
    /// while retaining the stable logical URL used in the DPoP proof.
    pub fn with_listener(origin: &str, listener: &str) -> anyhow::Result<Self> {
        let url = loopback_origin(origin)?;
        let target = loopback_origin(listener)?;
        let mut http = Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5));
        if url != target {
            anyhow::ensure!(url.scheme() == "http" && target.scheme() == "http", "Expected HTTP loopback forwarding");
            http = http.proxy(reqwest::Proxy::all(target)?);
        }
        Ok(Self { endpoint: url.join("/oauth/token")?, http: http.build()? })
    }

    pub(super) fn origin(&self) -> String {
        self.endpoint.origin().ascii_serialization()
    }

    pub(super) fn xrpc(&self, method: Method, nsid: &str) -> Option<reqwest::RequestBuilder> {
        Some(self.http.request(method, self.endpoint.join(&format!("/xrpc/{nsid}")).ok()?))
    }

    pub(super) async fn scoped(
        &self,
        key: &SigningKey,
        access: &str,
        request: reqwest::RequestBuilder,
    ) -> Option<reqwest::Response> {
        let mut request = request.build().ok()?;
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("DPoP {access}")).ok()?;
        authorization.set_sensitive(true);
        request.headers_mut().insert(reqwest::header::AUTHORIZATION, authorization);
        let retry = request.try_clone()?;
        let proof_header = proof(key, request.url(), request.method(), None, Some(access))?;
        request.headers_mut().insert("DPoP", proof_header.parse().ok()?);
        let response = self.http.execute(request).await.ok()?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED
            || !response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|header| header.to_str().ok())
                .is_some_and(|challenge| {
                    challenge.starts_with("DPoP ") && challenge.contains("error=\"use_dpop_nonce\"")
                })
        {
            return Some(response);
        }
        let nonce = response.headers().get("DPoP-Nonce")?.to_str().ok()?;
        let mut request = retry;
        let proof_header = proof(key, request.url(), request.method(), Some(nonce), Some(access))?;
        request.headers_mut().insert("DPoP", proof_header.parse().ok()?);
        self.http.execute(request).await.ok()
    }

    pub async fn par(&self, key: &SigningKey, params: &[(&str, &str)]) -> Option<String> {
        let endpoint = self.endpoint.join("/oauth/par").ok()?;
        let response = self.post(key, &endpoint, params).await?;
        if response.status() != reqwest::StatusCode::CREATED {
            return None;
        }
        let body: serde_json::Value = response.json().await.ok()?;
        body["request_uri"].as_str().map(str::to_owned)
    }

    /// Exchange a code taken from the verified callback using server-held PKCE.
    pub async fn exchange(
        &self,
        key: &SigningKey,
        client: &str,
        redirect: &str,
        code: &str,
        verifier: &str,
    ) -> Option<Tokens> {
        self.token(
            key,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", client),
                ("redirect_uri", redirect),
                ("code", code),
                ("code_verifier", verifier),
            ],
        )
        .await
    }

    pub async fn refresh(&self, key: &SigningKey, client: &str, refresh: &str) -> Option<Tokens> {
        self.token(key, &[("grant_type", "refresh_token"), ("client_id", client), ("refresh_token", refresh)]).await
    }

    async fn token(&self, key: &SigningKey, params: &[(&str, &str)]) -> Option<Tokens> {
        let response = self.post(key, &self.endpoint, params).await?;
        if !response.status().is_success() {
            return None;
        }
        let token: TokenResponse = response.json().await.ok()?;
        (token.token_type == "DPoP" && !token.refresh_token.is_empty() && !token.access_token.is_empty()).then(|| {
            Tokens {
                access: Zeroizing::new(token.access_token),
                refresh: Zeroizing::new(token.refresh_token),
                scope: token.scope,
            }
        })
    }

    async fn post(&self, key: &SigningKey, endpoint: &Url, params: &[(&str, &str)]) -> Option<reqwest::Response> {
        let mut nonce = None;
        for attempt in 0..2 {
            let proof = proof(key, endpoint, &Method::POST, nonce.as_deref(), None)?;
            let response = self.http.post(endpoint.clone()).header("DPoP", proof).form(params).send().await.ok()?;
            if response.status().is_success() {
                return Some(response);
            }
            if attempt != 0 || response.status() != reqwest::StatusCode::BAD_REQUEST {
                return None;
            }
            nonce = response.headers().get("DPoP-Nonce").and_then(|value| value.to_str().ok()).map(str::to_owned);
            let error: serde_json::Value = response.json().await.ok()?;
            // Only an explicit protocol challenge is safe to retry. A network
            // failure or other issuer response may have already consumed the grant.
            if nonce.is_none() || error["error"] != "use_dpop_nonce" {
                return None;
            }
        }
        None
    }
}

fn loopback_origin(origin: &str) -> anyhow::Result<Url> {
    let url = Url::parse(origin)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str() == Some("127.0.0.1")
            && url.origin().ascii_serialization() == origin,
        "Expected a canonical loopback OAuth origin"
    );
    Ok(url)
}

fn proof(
    key: &SigningKey,
    endpoint: &Url,
    method: &Method,
    nonce: Option<&str>,
    access: Option<&str>,
) -> Option<String> {
    let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jose::key_to_jwk(key.verifying_key())});
    let mut claims = json!({
        "jti": util::random_id("dpop-", 16),
        "htm": method.as_str(),
        "htu": jose::normalize_htu(endpoint.as_str())?,
        "iat": util::now_secs(),
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    if let Some(access) = access {
        claims["ath"] = json!(util::b64u(Sha256::digest(access.as_bytes())));
    }
    let input =
        format!("{}.{}", util::b64u(serde_json::to_vec(&header).ok()?), util::b64u(serde_json::to_vec(&claims).ok()?),);
    let signature: Signature = key.try_sign(input.as_bytes()).ok()?;
    Some(format!("{input}.{}", util::b64u(signature.to_bytes())))
}
