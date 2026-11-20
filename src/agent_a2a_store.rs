//! Durable A2A decisions in the PDS's existing owner-routed private CAS log.
//! No local SQLite, public repo rows, or retries of an ambiguous dispatch.
use crate::xrpc::{
    cas::{Cond, Op},
    App,
};
use bytes::Bytes;
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use vlatproto::xrpc::XrpcError;

const COUNT: &str = "agent-a2a/v1/count";
const INFLIGHT: &str = "agent-a2a/v1/inflight";
#[derive(Debug)]
pub enum Reservation {
    Fresh { row: String, pending: Bytes },
    Cached(J),
    Pending,
    Busy,
    Full,
    Conflict,
}
fn event_row(caller: &str, id: &str) -> String {
    let data = serde_json::to_vec(&(caller, id)).expect("strings serialize");
    format!("agent-a2a/v1/event/{}", hex::encode(Sha256::digest(data)))
}
/// `routing` is the configured recipient DID, never selected by request JSON.
pub async fn reserve(
    app: &App,
    routing: &str,
    caller: &str,
    id: &str,
    digest: &str,
    capacity: u32,
) -> Result<Reservation, XrpcError> {
    if !(1..=100000).contains(&capacity) {
        return Err(XrpcError::internal("Invalid decision quota"));
    }
    let row = event_row(caller, id);
    for _ in 0..16 {
        if let Some(raw) = app.get_private(routing, &row).await? {
            let value: J = serde_json::from_slice(&raw).map_err(XrpcError::from_err)?;
            if value["requestDigest"] != digest {
                return Ok(Reservation::Conflict);
            }
            return Ok(if value["state"] == "done" {
                Reservation::Cached(value["reply"].clone())
            } else {
                Reservation::Pending
            });
        }
        if app.get_private(routing, INFLIGHT).await?.is_some() {
            return Ok(Reservation::Busy);
        }
        let count_raw = app.get_private(routing, COUNT).await?;
        let count = match &count_raw {
            Some(raw) => serde_json::from_slice::<u32>(raw).map_err(XrpcError::from_err)?,
            None => 0,
        };
        if count >= capacity {
            return Ok(Reservation::Full);
        }
        let pending = Bytes::from(
            serde_json::to_vec(&json!({"state":"pending","caller":caller,"clientRequestId":id,"requestDigest":digest}))
                .unwrap(),
        );
        let outcome = app
            .private_cas(
                routing,
                vec![Cond::eq(&row, None), Cond::eq(INFLIGHT, None), Cond::eq(COUNT, count_raw)],
                vec![
                    Op::put(&row, Some(pending.clone())),
                    Op::put(INFLIGHT, Some(Bytes::from(row.clone()))),
                    Op::put(COUNT, Some(Bytes::from(serde_json::to_vec(&(count + 1)).unwrap()))),
                ],
            )
            .await?;
        if outcome.applied {
            return Ok(Reservation::Fresh { row, pending });
        }
    }
    Err(XrpcError::internal("A2A reservation contention"))
}
pub async fn finish(app: &App, routing: &str, row: &str, pending: Bytes, reply: &J) -> Result<(), XrpcError> {
    let mut decision: J = serde_json::from_slice(&pending).map_err(XrpcError::from_err)?;
    decision["state"] = json!("done");
    decision["reply"] = reply.clone();
    let outcome = app
        .private_cas(
            routing,
            vec![Cond::eq(row, Some(pending)), Cond::eq(INFLIGHT, Some(Bytes::from(row.to_string())))],
            vec![
                Op::put(row, Some(Bytes::from(serde_json::to_vec(&decision).map_err(XrpcError::from_err)?))),
                Op::put(INFLIGHT, None),
            ],
        )
        .await?;
    if !outcome.applied {
        return Err(XrpcError::internal("A2A decision commit refused; reconcile pending"));
    }
    Ok(())
}
