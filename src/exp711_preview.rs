//! Explicit loopback startup profile for the isolated EXP-711 PDS.

use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use vlpds::{
    oauth::client::{PreviewClient, PREVIEW_CALLBACK, PREVIEW_CLIENT_PATH, PREVIEW_LOGIN_CLIENT_PATH},
    xrpc::{
        agent_chat::{credentials, oauth_client::LoopbackOAuth},
        agent_dispatch::Binding,
        agent_grant_recovery::http::Mount,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Profile {
    pub recovery_listen: SocketAddr,
    storage: Storage,
    pub wrapping_key_file: PathBuf,
    issuer: String,
    dispatch_signer: Option<String>,
    enrollment_redirect: Option<String>,
    https_enrollment: Option<HttpsEnrollment>,
    service_token_file: PathBuf,
    bindings: HashMap<String, Binding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HttpsEnrollment {
    pds_issuer: String,
    fixture_tls: Option<FixtureTls>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FixtureTls {
    ca_file: PathBuf,
    listener: SocketAddr,
    plc_origin: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Storage {
    endpoint: String,
    bucket: String,
    access_key_file: PathBuf,
    secret_key_file: PathBuf,
}

impl Profile {
    pub fn load(path: &std::path::Path, listen: &str) -> anyhow::Result<Self> {
        let profile: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        let public: SocketAddr = listen.parse()?;
        anyhow::ensure!(
            public.ip().is_loopback()
                && profile.recovery_listen.ip().is_loopback()
                && public != profile.recovery_listen,
            "EXP-711 requires separate loopback PDS and recovery listeners"
        );
        anyhow::ensure!(
            profile.storage.access_key_file.is_absolute()
                && profile.storage.secret_key_file.is_absolute()
                && profile.wrapping_key_file.is_absolute()
                && profile.service_token_file.is_absolute(),
            "EXP-711 profile paths must be absolute"
        );
        for (owner, binding) in &profile.bindings {
            anyhow::ensure!(
                vlatproto::syntax::valid_did(owner)
                    && vlatproto::syntax::valid_did(&binding.agent)
                    && vlatproto::syntax::parse_space_uri(&binding.space)
                        .is_some_and(|space| space.authority == owner && space.record.is_none()),
                "Invalid EXP-711 owner binding"
            );
        }
        Ok(profile)
    }

    pub fn check_hardened(&self, args: &crate::Args) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.https_enrollment.is_some() && self.https_client(&args.public_url)?.is_some(),
            "Hardened EXP-711 requires isolated HTTPS enrollment"
        );
        anyhow::ensure!(
            args.admin_listen.is_none() && args.admin_proxy_header.is_none(),
            "Hardened EXP-711 does not expose an admin listener or trust admin proxy headers"
        );
        let files = [
            ("--jwt-secret-file", &args.jwt_secret_file),
            ("--admin-token-file", &args.admin_token_file),
            ("--internal-token-file", &args.internal_token_file),
            ("--plc-rotation-key-file", &args.plc_rotation_key_file),
        ];
        for (flag, path) in files {
            anyhow::ensure!(
                path.as_ref().is_some_and(|path| path.is_absolute()),
                "Hardened EXP-711 requires an absolute preview-only {flag}"
            );
        }
        let bridge = std::fs::read_to_string(&self.service_token_file)?;
        let bridge = bridge.trim_end();
        for secret in [&args.jwt_secret, &args.admin_token, &args.internal_token] {
            anyhow::ensure!(secret.as_deref() != Some(bridge), "EXP-711 bridge token must be distinct");
        }
        let plc = reqwest::Url::parse(&args.plc_url)?;
        anyhow::ensure!(
            plc.scheme() == "https" || self.is_local_tls_fixture(&args.plc_url),
            "Hardened EXP-711 requires HTTPS PLC outside a pinned local TLS fixture"
        );
        Ok(())
    }

    pub fn is_local_tls_fixture(&self, plc_url: &str) -> bool {
        self.https_enrollment.as_ref().and_then(|https| https.fixture_tls.as_ref()).is_some_and(|tls| {
            tls.listener.ip().is_loopback()
                && tls.plc_origin.as_deref() == Some(plc_url)
                && reqwest::Url::parse(plc_url).is_ok_and(|url| {
                    url.scheme() == "http"
                        && url.host_str() == Some("127.0.0.1")
                        && url.port().is_some()
                        && url.origin().ascii_serialization() == plc_url
                        && url.username().is_empty()
                        && url.password().is_none()
                })
        })
    }

    pub fn store(&self) -> anyhow::Result<vlsync_store::store::S3Config> {
        let endpoint = reqwest::Url::parse(&self.storage.endpoint)?;
        anyhow::ensure!(
            endpoint.scheme() == "http"
                && endpoint.host_str() == Some("127.0.0.1")
                && endpoint.port().is_some()
                && endpoint.origin().ascii_serialization() == self.storage.endpoint
                && self.storage.bucket.starts_with("exp711-"),
            "EXP-711 requires an explicit loopback S3 endpoint and an exp711-* bucket"
        );
        Ok(vlsync_store::store::S3Config {
            endpoint: self.storage.endpoint.clone(),
            bucket: self.storage.bucket.clone(),
            access_key: std::fs::read_to_string(&self.storage.access_key_file)?.trim_end().into(),
            secret_key: std::fs::read_to_string(&self.storage.secret_key_file)?.trim_end().into(),
            region: "us-east-1".into(),
        })
    }

    pub fn schedule_cleanup(&self, app: std::sync::Arc<vlpds::xrpc::App>) -> tokio::task::JoinHandle<()> {
        let bindings = self.bindings.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                for (owner, binding) in &bindings {
                    let result = match vlpds::xrpc::agent_chat::rotation::Rotation::new(&app, owner, binding) {
                        Ok(rotation) => rotation.drain_local_retirements(16).await,
                        Err(error) => Err(error),
                    };
                    if result.is_err() {
                        tracing::warn!("EXP-711 retirement scan deferred");
                    }
                }
            }
        })
    }

    pub fn https_client(&self, origin: &str) -> anyhow::Result<Option<PreviewClient>> {
        let Some(https) = &self.https_enrollment else { return Ok(None) };
        anyhow::ensure!(
            https.pds_issuer == origin && origin != self.issuer && self.dispatch_signer.is_some(),
            "EXP-711 HTTPS issuer must match the isolated PDS public URL and differ from the MCP issuer"
        );
        let redirect = self
            .enrollment_redirect
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Missing preview enrollment callback"))?;
        let mut scopes = std::collections::BTreeSet::from(["atproto".to_owned()]);
        for binding in self.bindings.values() {
            let scope = credentials::requested_scope(binding)
                .ok_or_else(|| anyhow::anyhow!("Invalid scoped preview binding"))?;
            scopes.extend(scope.split_whitespace().map(str::to_owned));
        }
        PreviewClient::new(origin, redirect, scopes.into_iter().collect::<Vec<_>>().join(" ")).map(Some)
    }

    fn transport(&self, origin: &str) -> anyhow::Result<LoopbackOAuth> {
        let Some(https) = &self.https_enrollment else { return LoopbackOAuth::new(origin) };
        if let Some(tls) = &https.fixture_tls {
            anyhow::ensure!(tls.ca_file.is_absolute(), "Expected absolute isolated TLS fixture CA path");
            let ca = reqwest::Certificate::from_pem(&std::fs::read(&tls.ca_file)?)?;
            return LoopbackOAuth::https(origin, Some(ca), Some(tls.listener));
        }
        LoopbackOAuth::https(origin, None, None)
    }

    pub fn dispatch(&self, origin: &str) -> anyhow::Result<Option<vlpds::xrpc::agent_dispatch_route::Mount>> {
        self.dispatch_signer
            .as_deref()
            .map(|signer| {
                vlpds::xrpc::agent_dispatch_route::Mount::preview_runtime(signer, &self.issuer, self.transport(origin)?)
            })
            .transpose()
    }

    pub fn recovery(&self, origin: &str, client: Option<&PreviewClient>) -> anyhow::Result<Mount> {
        let token = std::fs::read_to_string(&self.service_token_file)?;
        let bindings = self.bindings.clone();
        let mount = Mount::new(&self.issuer, token.trim_end(), move |owner| bindings.get(owner).cloned())?;
        if let Some(client) = client {
            return Ok(mount.with_https_enrollment(client, self.transport(origin)?));
        }
        match &self.enrollment_redirect {
            Some(redirect) => mount.with_enrollment(redirect.clone()),
            None => Ok(mount),
        }
    }
}

#[derive(Deserialize)]
struct Callback {
    code: String,
    state: String,
    iss: String,
}

impl Profile {
    pub fn callback(&self, pds_origin: &str, client: Option<&PreviewClient>) -> anyhow::Result<axum::Router> {
        use axum::{extract::Query, response::Html, routing::get};
        if self.dispatch_signer.is_none() {
            return Ok(axum::Router::new());
        }
        let mut router = axum::Router::new();
        if let Some(client) = client {
            let metadata = client.metadata();
            let identity = client.identity().metadata();
            router = router
                .route(PREVIEW_CLIENT_PATH, get(move || async move { axum::Json(metadata) }))
                .route(PREVIEW_LOGIN_CLIENT_PATH, get(move || async move { axum::Json(identity) }));
        }
        anyhow::ensure!(
            self.enrollment_redirect.as_deref() == Some(format!("{pds_origin}{PREVIEW_CALLBACK}").as_str()),
            "EXP-711 chat requires the exact PDS callback URI"
        );
        let relay = reqwest::Url::parse(&format!("{}/spaces-callback", self.issuer))?;
        let issuer = pds_origin.to_owned();
        Ok(router.route(
            PREVIEW_CALLBACK,
            get(move |Query(input): Query<Callback>| async move {
                if input.iss != issuer
                    || ![&input.code, &input.state].iter().all(|value| {
                        !value.is_empty()
                            && value.len() <= 512
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                    })
                {
                    return Err(axum::http::StatusCode::BAD_REQUEST);
                }
                Ok((
                    [
                        ("cache-control", "no-store".to_owned()),
                        ("referrer-policy", "origin".to_owned()),
                        (
                            "content-security-policy",
                            format!(
                                "default-src 'none'; form-action {}; frame-ancestors 'none'; base-uri 'none'",
                                relay.origin().ascii_serialization()
                            ),
                        ),
                    ],
                    Html(format!(
                        r#"<!doctype html><meta charset="utf-8"><title>Return to Spaces preview</title>
<form method="post" action="{relay}">
<input type="hidden" name="code" value="{}">
<input type="hidden" name="state" value="{}">
<input type="hidden" name="issuer" value="{issuer}">
<button>Return to Spaces preview</button>
</form>"#,
                        input.code, input.state
                    )),
                ))
            }),
        ))
    }
}
