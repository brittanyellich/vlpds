//! Explicit loopback startup profile for the isolated EXP-711 PDS.

use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use vlpds::xrpc::{agent_dispatch::Binding, agent_grant_recovery::http::Mount};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Profile {
    pub recovery_listen: SocketAddr,
    storage: Storage,
    pub wrapping_key_file: PathBuf,
    issuer: String,
    dispatch_signer: Option<String>,
    enrollment_redirect: Option<String>,
    service_token_file: PathBuf,
    bindings: HashMap<String, Binding>,
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

    pub fn dispatch(&self, origin: &str) -> anyhow::Result<Option<vlpds::xrpc::agent_dispatch_route::Mount>> {
        self.dispatch_signer
            .as_deref()
            .map(|signer| {
                vlpds::xrpc::agent_chat::oauth_client::LoopbackOAuth::new(origin)?;
                vlpds::xrpc::agent_dispatch_route::Mount::preview_runtime(signer, &self.issuer, origin.into())
            })
            .transpose()
    }

    pub fn recovery(&self) -> anyhow::Result<Mount> {
        let token = std::fs::read_to_string(&self.service_token_file)?;
        let bindings = self.bindings.clone();
        let mount = Mount::new(&self.issuer, token.trim_end(), move |owner| bindings.get(owner).cloned())?;
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
    pub fn callback(&self, pds_origin: &str) -> anyhow::Result<axum::Router> {
        use axum::{extract::Query, response::Html, routing::get};
        if self.dispatch_signer.is_none() {
            return Ok(axum::Router::new());
        }
        const PATH: &str = "/exp711/spaces-callback";
        anyhow::ensure!(
            self.enrollment_redirect.as_deref() == Some(format!("{pds_origin}{PATH}").as_str()),
            "EXP-711 chat requires the private loopback PDS callback URI"
        );
        let relay = reqwest::Url::parse(&format!("{}/spaces-callback", self.issuer))?;
        let issuer = pds_origin.to_owned();
        Ok(axum::Router::new().route(
            PATH,
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
