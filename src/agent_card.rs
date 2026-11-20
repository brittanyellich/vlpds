//! A2A1.0 JCS Card signature with an experimental DID binding, constrained to our exact native
//! template. No private Card key or Card-supplied trust/key URL is accepted.
use crate::{
    agent_contact_pilot::{AGENT_PATH, CARD_PATH},
    agent_endorsement::AGENT,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde_json::{json, Value as J};
pub const IDENTITY: &str = "urn:atagents:experimental:a2a-agent-did:v1";
pub fn template(origin: &str, audience: &str) -> J {
    json!({"name":"Identity test agent","version":"0.1.0","description":"Fixed read-only identity resolution; discovery does not grant access",
 "supportedInterfaces":[{"url":format!("{origin}{AGENT_PATH}"),"protocolBinding":"JSONRPC","protocolVersion":"1.0"}],
 "capabilities":{"extensions":[{"uri":IDENTITY,"params":{"did":AGENT}},{"uri":"urn:atagents:experimental:service-auth:v1","required":true,"params":{"aud":audience,"lxm":"chat.atagents.agent.contact","maxTokenLifetimeSeconds":60}}]},
 "defaultInputModes":["application/json"],"defaultOutputModes":["application/json"],
 "skills":[{"id":"resolve-identity-test","name":"Resolve fixed agent relationship","description":"Native signed endorsement checks, with separate private Kody profile assertion","tags":["identity"]}],
 "securitySchemes":{"atprotoService":{"httpAuthSecurityScheme":{"scheme":"bearer","bearerFormat":"JWT"}}},"securityRequirements":[{"schemes":{"atprotoService":{}}}]})
}
fn canonical(value: &J) -> String {
    match value {
        J::Object(o) => {
            let mut keys = o.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(&o[k])))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        J::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
        _ => serde_json::to_string(value).unwrap(),
    }
}
pub fn payload(card: &J) -> Result<String, String> {
    let mut value = card.clone();
    value.as_object_mut().ok_or("Card object required")?.remove("signatures");
    Ok(B64.encode(canonical(&value).as_bytes()))
}
pub fn validate_pin(pin: &str) -> Result<(), String> {
    if !pin.starts_with('z') || pin.len() > 128 {
        return Err("P256 Card pin required".into());
    }
    let bytes = bs58::decode(&pin[1..]).into_vec().map_err(|_| "Invalid Card multikey")?;
    if bytes.len() != 35 || bytes[..2] != [0x80, 0x24] || !matches!(bytes[2], 2 | 3) {
        return Err("P256 Card pin required".into());
    }
    Ok(())
}
pub fn current_key(document: &J) -> Result<Option<String>, String> {
    if document["id"] != AGENT {
        return Err("Wrong Card DID authority response".into());
    }
    if document.get("deactivated").is_some_and(|v| !v.is_boolean()) {
        return Err("Invalid Card deactivation metadata".into());
    }
    if document["deactivated"] == true {
        return Ok(None);
    }
    let methods = match document.get("verificationMethod") {
        None => return Ok(None),
        Some(J::Array(a)) if a.len() <= 64 => a,
        _ => return Err("Invalid Card methods".into()),
    };
    let mut matching = methods.iter().filter(|m| m["id"] == format!("{AGENT}#card-signing"));
    let Some(m) = matching.next() else { return Ok(None) };
    if matching.next().is_some() || m["controller"] != AGENT || m["type"] != "Multikey" {
        return Err("Ambiguous or uncontrolled Card key".into());
    }
    let key = m["publicKeyMultibase"].as_str().ok_or("Missing Card key")?;
    validate_pin(key)?;
    Ok(Some(key.into()))
}
pub fn verify_origin(document: &J, origin: &str) -> Result<(), String> {
    let services = document["service"].as_array().filter(|a| a.len() <= 64).ok_or("Missing Card PDS service")?;
    let mut pds = services.iter().filter(|s| s["id"] == "#atproto_pds" || s["id"] == format!("{AGENT}#atproto_pds"));
    let s = pds.next().ok_or("Missing Card PDS service")?;
    if pds.next().is_some() || s["type"] != "AtprotoPersonalDataServer" || s["serviceEndpoint"] != origin {
        return Err("Card origin is not the current PDS".into());
    }
    Ok(())
}

pub fn verify(card: &J, pin: &str, origin: &str, audience: &str) -> Result<(), String> {
    validate_pin(pin)?;
    if serde_json::to_vec(card).map_err(|_| "Invalid Card")?.len() > 8192 {
        return Err("Card byte limit".into());
    }
    let mut raw = card.clone();
    raw.as_object_mut().ok_or("Card object required")?.remove("signatures");
    if raw != template(origin, audience) {
        return Err("Card does not match exact native template/endpoint".into());
    }
    let signatures = card["signatures"].as_array().filter(|a| a.len() == 1).ok_or("One Card signature required")?;
    let s = signatures[0]
        .as_object()
        .filter(|o| o.len() == 2 && o.contains_key("protected") && o.contains_key("signature"))
        .ok_or("Invalid Card signature object")?;
    let protected = s["protected"].as_str().ok_or("Protected header required")?;
    let raw_header = B64.decode(protected).map_err(|_| "Invalid protected encoding")?;
    let expected = format!("{{\"alg\":\"ES256\",\"typ\":\"JOSE\",\"kid\":\"{AGENT}#card-signing\"}}");
    if raw_header != expected.as_bytes() || B64.encode(&raw_header) != protected {
        return Err("Invalid protected Card header".into());
    }
    let signature = s["signature"].as_str().ok_or("Signature required")?;
    let bytes = B64.decode(signature).map_err(|_| "Invalid signature encoding")?;
    if bytes.len() != 64 || B64.encode(&bytes) != signature {
        return Err("Raw64 canonical signature required".into());
    }
    let input = format!("{protected}.{}", payload(card)?);
    if !vlatproto::crypto::verify_multikey(pin, input.as_bytes(), &bytes, false)? {
        return Err("Card signature rejected".into());
    }
    Ok(())
}
pub fn card_url(origin: &str) -> String {
    format!("{origin}{CARD_PATH}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_production_did_card_synthetic_key_and_tampering() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let key = SigningKey::from_bytes((&rand::random::<[u8; 32]>()).into()).unwrap();
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(key.verifying_key().to_sec1_point(true).as_bytes());
        let pin = format!("z{}", bs58::encode(multikey).into_string());
        let origin = "https://pds.crate.social";
        let aud = "did:web:pds.crate.social";
        let mut card = template(origin, aud);
        let protected = B64.encode(format!("{{\"alg\":\"ES256\",\"typ\":\"JOSE\",\"kid\":\"{AGENT}#card-signing\"}}"));
        let sig: Signature = key.sign(format!("{protected}.{}", payload(&card).unwrap()).as_bytes());
        let sig = sig.normalize_s();
        card["signatures"] = json!([{"protected":protected,"signature":B64.encode(sig.to_bytes())}]);
        verify(&card, &pin, origin, aud).unwrap();
        let document = json!({"id":AGENT,"verificationMethod":[{"id":format!("{AGENT}#card-signing"),"type":"Multikey","controller":AGENT,"publicKeyMultibase":pin}],"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":origin}]});
        assert_eq!(current_key(&document).unwrap(), Some(pin.clone()));
        let mut changed = card.clone();
        changed["supportedInterfaces"][0]["url"] = json!("https://other.invalid/a2a");
        assert!(verify(&changed, &pin, origin, aud).is_err());
        let mut changed = card.clone();
        changed["name"] = json!("tampered");
        assert!(verify(&changed, &pin, origin, aud).is_err());
        let mut changed = card.clone();
        changed["signatures"][0]["signature"] = json!(B64.encode([0u8; 64]));
        assert!(verify(&changed, &pin, origin, aud).is_err());
        let mut changed = document.clone();
        changed["verificationMethod"][0]["controller"] = json!(crate::agent_endorsement::PRINCIPAL);
        assert!(current_key(&changed).is_err());
        if let Ok(path) = std::env::var("VLPDS_AGENT_CARD_VECTOR_PATH") {
            std::fs::write(path,serde_json::to_vec_pretty(&json!({"signedCard":card,"publicPin":pin,"syntheticDidDocument":document,"template":template(origin,aud),"publicSec1Hex":hex::encode(key.verifying_key().to_sec1_point(true).as_bytes()),"keyOrigin":"Disposable synthetic P256; never a live DID key"})).unwrap()).unwrap();
        }
    }
}

// A pin is retired monotonically, never automatically reactivated. Explicit
// new-key configuration is required on rotation; old pins remain denied even
// after a process restart or a later authority rollback to that key.
pub async fn is_retired(app: &crate::xrpc::App, routing: &str, pin: &str) -> Result<bool, String> {
    use sha2::{Digest, Sha256};
    let count = app
        .get_private(routing, "agent-a2a/v1/card-history/count")
        .await
        .map_err(|_| "Card trust store unavailable")?;
    let count = match count {
        Some(b) => serde_json::from_slice::<u32>(&b).map_err(|_| "Invalid Card trust state")?,
        None => 0,
    };
    if count >= 64 {
        return Err("Card key history capacity; operator security recovery required".into());
    }
    let row = format!("agent-a2a/v1/card-history/retired/{}", hex::encode(Sha256::digest(pin.as_bytes())));
    Ok(app.get_private(routing, &row).await.map_err(|_| "Card trust store unavailable")?.is_some())
}
pub async fn retire(app: &crate::xrpc::App, routing: &str, pin: &str) -> Result<(), String> {
    use crate::xrpc::cas::{Cond, Op};
    use bytes::Bytes;
    use sha2::{Digest, Sha256};
    let row = format!("agent-a2a/v1/card-history/retired/{}", hex::encode(Sha256::digest(pin.as_bytes())));
    let counter = "agent-a2a/v1/card-history/count";
    for _ in 0..16 {
        if app.get_private(routing, &row).await.map_err(|_| "Card trust store unavailable")?.is_some() {
            return Ok(());
        }
        let raw = app.get_private(routing, counter).await.map_err(|_| "Card trust store unavailable")?;
        let count = match &raw {
            Some(b) => serde_json::from_slice::<u32>(b).map_err(|_| "Invalid Card trust state")?,
            None => 0,
        };
        if count >= 64 {
            return Err("Card history capacity".into());
        }
        let out = app
            .private_cas(
                routing,
                vec![Cond::eq(&row, None), Cond::eq(counter, raw)],
                vec![
                    Op::put(&row, Some(Bytes::from_static(b"retired"))),
                    Op::put(counter, Some(Bytes::from(serde_json::to_vec(&(count + 1)).unwrap()))),
                ],
            )
            .await
            .map_err(|_| "Card trust write refused")?;
        if out.applied {
            return Ok(());
        }
    }
    Err("Card trust contention".into())
}

#[derive(Clone)]
pub struct SignedCard {
    card: std::sync::Arc<J>,
    pin: String,
    cache: std::sync::Arc<tokio::sync::Mutex<(Option<std::time::Instant>, std::time::Instant)>>,
}
impl SignedCard {
    pub fn new(card: J, pin: String) -> Result<Self, String> {
        validate_pin(&pin)?;
        if serde_json::to_vec(&card).map_err(|_| "Invalid Card")?.len() > 8192 {
            return Err("Card limit".into());
        }
        Ok(Self {
            card: std::sync::Arc::new(card),
            pin,
            cache: std::sync::Arc::new(tokio::sync::Mutex::new((None, std::time::Instant::now()))),
        })
    }
    pub async fn checked(&self, app: &crate::xrpc::App, origin: &str) -> Result<J, String> {
        use std::time::{Duration, Instant};
        let mut state = self.cache.lock().await;
        // Recheck immutable template/audience even on a cached authority snapshot.
        verify(&self.card, &self.pin, origin, &app.jwt.service_did)?;
        if is_retired(app, AGENT, &self.pin).await? {
            state.0 = None;
            return Err("Retired Card key cannot return".into());
        }
        if state.0.is_some_and(|until| Instant::now() < until) {
            return Ok((*self.card).clone());
        }
        state.0 = None;
        if Instant::now() < state.1 {
            return Err("Card authority cooldown; no stale fallback".into());
        }
        state.1 = Instant::now() + Duration::from_secs(1);
        let document = crate::agent_endorsement_fetch::card_document().await?;
        let key = match &document {
            Some(d) => current_key(d)?,
            None => None,
        };
        if key.as_deref() != Some(self.pin.as_str()) {
            retire(app, AGENT, &self.pin).await?;
            return Err("Card key changed or removed; explicit new pin/Card required".into());
        }
        verify_origin(document.as_ref().unwrap(), origin)?;
        verify(&self.card, &self.pin, origin, &app.jwt.service_did)?;
        if is_retired(app, AGENT, &self.pin).await? {
            return Err("Card key retired during verification".into());
        }
        state.0 = Some(Instant::now() + Duration::from_secs(5));
        Ok((*self.card).clone())
    }
}
