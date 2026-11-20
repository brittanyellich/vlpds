//! Private fixed endpoint with HMAC-authenticated boot challenge and responses.
use crate::agent_endorsement::{AGENT, PRINCIPAL};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::time::Duration;
const DOMAIN: &str = "atagents/private-profile/v1";
const CHALLENGE: &str = "/private/agent-profile/challenge";
const ASSERT: &str = "/private/agent-profile/assert";
#[derive(Clone)]
pub struct Bridge {
    origin: String,
    key: Vec<u8>,
    client: reqwest::Client,
}
fn signature(key: &[u8], tuple: &J) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    m.update(&serde_json::to_vec(tuple).unwrap());
    hex::encode(m.finalize().into_bytes())
}
fn verify(key: &[u8], tuple: &J, sig: &str) -> Result<(), String> {
    let sig = hex::decode(sig).map_err(|_| "Invalid bridge signature")?;
    if sig.len() != 32 {
        return Err("Invalid bridge signature".into());
    }
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    m.update(&serde_json::to_vec(tuple).unwrap());
    m.verify_slice(&sig).map_err(|_| "Unauthenticated bridge response".into())
}
async fn body(mut r: reqwest::Response) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>), String> {
    if r.headers()
        .get("content-type")
        .and_then(|s| s.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        != Some("application/json".into())
        || r.status().is_redirection()
    {
        return Err("Invalid bridge response".into());
    }
    let status = r.status().as_u16();
    let headers = r.headers().clone();
    let mut b = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|_| "Bridge body error")? {
        if b.len() + c.len() > 4096 {
            return Err("Bridge body limit".into());
        }
        b.extend_from_slice(&c);
    }
    Ok((status, headers, b))
}
impl Bridge {
    pub fn new(origin: &str, key: Vec<u8>) -> anyhow::Result<Self> {
        let u = reqwest::Url::parse(origin)?;
        anyhow::ensure!(
            u.scheme() == "http"
                && u.host_str() == Some("127.0.0.1")
                && u.port().is_some_and(|p| p >= 1024)
                && u.origin().ascii_serialization() == origin
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none(),
            "Exact private loopback bridge origin required"
        );
        anyhow::ensure!(key.len() == 32, "Dedicated 32-byte bridge key required");
        Ok(Self {
            origin: origin.into(),
            key,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(65))
                .build()?,
        })
    }
    pub async fn assert_profile(&self, event_id: &str) -> Result<(), String> {
        if event_id.len() != 64 || !event_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err("Invalid fixed event id".into());
        }
        let (status, _, bytes) = body(
            self.client
                .get(format!("{}{CHALLENGE}", self.origin))
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .map_err(|_| "Private bridge unavailable")?,
        )
        .await?;
        if status != 200 {
            return Err("Private bridge unavailable".into());
        }
        let c: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid bridge challenge")?;
        let boot = c["boot"]
            .as_str()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
            .ok_or("Invalid boot epoch")?;
        verify(
            &self.key,
            &json!([DOMAIN, "challenge", "GET", CHALLENGE, boot]),
            c["signature"].as_str().ok_or("Missing challenge signature")?,
        )?;
        let timestamp = (vlatproto::tid::now_micros() / 1_000_000).to_string();
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        let data = serde_json::to_vec(
            &json!({"eventId":event_id,"agentDid":AGENT,"principalDid":PRINCIPAL,"skillId":"resolve-identity-test"}),
        )
        .unwrap();
        let hash = hex::encode(Sha256::digest(&data));
        let sig = signature(&self.key, &json!([DOMAIN, "request", "POST", ASSERT, boot, timestamp, nonce, hash]));
        let (status, headers, bytes) = body(
            self.client
                .post(format!("{}{ASSERT}", self.origin))
                .header("content-type", "application/json")
                .header("x-agent-bridge-boot", boot)
                .header("x-agent-bridge-timestamp", &timestamp)
                .header("x-agent-bridge-nonce", &nonce)
                .header("x-agent-bridge-signature", sig)
                .body(data)
                .send()
                .await
                .map_err(|_| "Private assertion unavailable")?,
        )
        .await?;
        if headers.get_all("x-agent-bridge-signature").iter().count() != 1 {
            return Err("Missing or ambiguous response authentication".into());
        }
        verify(
            &self.key,
            &json!([
                DOMAIN,
                "response",
                "POST",
                ASSERT,
                boot,
                timestamp,
                nonce,
                hash,
                status,
                hex::encode(Sha256::digest(&bytes))
            ]),
            headers
                .get("x-agent-bridge-signature")
                .and_then(|v| v.to_str().ok())
                .ok_or("Missing response authentication")?,
        )?;
        if status != 200 {
            return Err("Profile assertion failed".into());
        }
        let value: J = serde_json::from_slice(&bytes).map_err(|_| "Invalid profile assertion")?;
        if value
            != json!({"eventId":event_id,"kind":"profile_asserted","profileId":"prf_642a5cf465fa4528a8f7e075f29557c4","agentDid":AGENT,"principalDid":PRINCIPAL})
        {
            return Err("Profile assertion correlation failed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Child, Command, Stdio};
    struct Fixture(Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[tokio::test]
    async fn node_rust_private_bridge_interop_authenticates_response() {
        let key = rand::random::<[u8; 32]>();
        let mut child = Fixture(
            Command::new("node")
                .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tools/agent-contact-pilot/production/bridge-fixture.mjs"))
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        child
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_string(&json!({"key":hex::encode(key)})).unwrap().as_bytes())
            .unwrap();
        let stdout = child.0.stdout.take().unwrap();
        let descriptor = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let mut line = String::new();
                BufReader::new(stdout).take(4096).read_line(&mut line).unwrap();
                serde_json::from_str::<J>(&line).unwrap()
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let origin = descriptor["origin"].as_str().unwrap();
        let bridge = Bridge::new(origin, key.to_vec()).unwrap();
        assert!(bridge.assert_profile(&"a".repeat(64)).await.is_ok());
        let wrong = Bridge::new(origin, rand::random::<[u8; 32]>().to_vec()).unwrap();
        assert!(wrong.assert_profile(&"b".repeat(64)).await.is_err());
        assert!(bridge.assert_profile("arbitrary-input").await.is_err());
    }
}
