//! Owner-scoped provisioning state and authenticated signup.

use super::authn::{Auth, Credentials};
use super::cas::{Cond, Op};
use super::{internal, server, App, AppState, XResult, XrpcError};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

const ROW: &str = "agent-provisioning/v1";
const MAX_RESERVATIONS: usize = 64;
const CAS_ATTEMPTS: usize = 32;
const OWNER_QUOTA: usize = 1;
pub(super) const ACCOUNT_MARKER: &str = "agentProvisioningProof";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum Status {
    Reserved,
    /// A signup may have run. An observer must reconcile, never dispatch it.
    InFlight,
    Ready {
        did: String,
    },
    /// PLC may have applied genesis. Automated retries stop here.
    PlcUncertain,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Reservation {
    pub handle: String,
    pub status: Status,
    // Monotonic, so a delayed outcome cannot finish a newer attempt.
    attempt: u64,
}

pub enum SignupOutcome {
    /// The caller has evidence that no account or external identity was made.
    RejectedBeforeCreation,
    /// The existing signup path confirmed the account and repo.
    Created { did: String },
    /// PLC may have registered the identity, or compensation is unconfirmed.
    PlcUncertain,
}

type Reservations = BTreeMap<String, Reservation>;

pub struct Journal<'a> {
    app: &'a App,
    owner: &'a str,
}

impl<'a> Journal<'a> {
    /// Internal storage API. Derive `owner` from a verified owner session.
    pub fn new(app: &'a App, owner: &'a str) -> Self {
        Self { app, owner }
    }

    async fn load(&self) -> XResult<(Option<Bytes>, Reservations)> {
        let bytes = self.app.get_private(self.owner, ROW).await?;
        let records = bytes.as_ref().map(|b| serde_json::from_slice(b)).transpose().map_err(XrpcError::from_err)?;
        Ok((bytes, records.unwrap_or_default()))
    }

    async fn update<T>(&self, change: impl Fn(&mut Reservations) -> XResult<(T, bool)>) -> XResult<T> {
        for _ in 0..CAS_ATTEMPTS {
            let (prior, mut records) = self.load().await?;
            let (result, changed) = change(&mut records)?;
            if !changed {
                return Ok(result);
            }
            let value = Bytes::from(serde_json::to_vec(&records).map_err(XrpcError::from_err)?);
            let outcome =
                self.app.private_cas(self.owner, vec![Cond::eq(ROW, prior)], vec![Op::put(ROW, Some(value))]).await?;
            if outcome.applied {
                return Ok(result);
            }
        }
        Err(XrpcError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "ProvisioningBusy".into(),
            message: "Provisioning reservations are busy; retry the operation".into(),
        })
    }

    /// Reserve with an atomic per-owner quota. Pending and uncertain rows
    /// count toward it, so ignoring a partial signup cannot free capacity.
    pub async fn reserve(&self, id: &str, handle: &str, quota: usize) -> XResult<Reservation> {
        validate_id(id)?;
        if !vlatproto::syntax::valid_handle(handle) || handle != handle.to_ascii_lowercase() {
            return Err(XrpcError::bad("InvalidHandle", "Expected a normalized handle"));
        }
        self.update(|records| {
            if let Some(existing) = records.get(id) {
                if existing.handle != handle {
                    return Err(conflict("This operation already reserved a different handle"));
                }
                return Ok((existing.clone(), false));
            }
            if records.len() >= quota.min(MAX_RESERVATIONS) {
                return Err(XrpcError::bad("AgentQuotaExceeded", "Owner provisioning quota reached"));
            }
            let reservation = Reservation { handle: handle.to_owned(), status: Status::Reserved, attempt: 0 };
            records.insert(id.to_owned(), reservation.clone());
            Ok((reservation, true))
        })
        .await
    }

    pub async fn get(&self, id: &str) -> XResult<Option<Reservation>> {
        validate_id(id)?;
        Ok(self.load().await?.1.remove(id))
    }

    /// Only the caller receiving `Some(attempt)` may submit signup. After a
    /// lost claim or signup response, `None` means stop and inspect status.
    pub async fn claim(&self, id: &str) -> XResult<Option<u64>> {
        validate_id(id)?;
        self.update(|records| {
            let record = existing(records, id)?;
            if record.status != Status::Reserved {
                return Ok((None, false));
            }
            record.attempt =
                record.attempt.checked_add(1).ok_or_else(|| XrpcError::internal("Provisioning attempt exhausted"))?;
            record.status = Status::InFlight;
            Ok((Some(record.attempt), true))
        })
        .await
    }

    /// Report a known result using the attempt that claimed signup. Retrying
    /// the same report is safe. Unknown transport/storage errors leave the
    /// claim in flight; they are never classified as definite rejection.
    pub async fn settle(&self, id: &str, attempt: u64, outcome: SignupOutcome) -> XResult<Reservation> {
        validate_id(id)?;
        let next = match outcome {
            SignupOutcome::RejectedBeforeCreation => Status::Reserved,
            SignupOutcome::Created { did } if vlatproto::syntax::valid_did(&did) && did != self.owner => {
                Status::Ready { did }
            }
            SignupOutcome::Created { .. } => return Err(XrpcError::bad("InvalidDid", "Expected a distinct agent DID")),
            SignupOutcome::PlcUncertain => Status::PlcUncertain,
        };
        self.update(|records| {
            let record = existing(records, id)?;
            if attempt == 0 || record.attempt != attempt {
                return Err(conflict("Provisioning attempt changed"));
            }
            if record.status == next {
                return Ok((record.clone(), false));
            }
            if record.status != Status::InFlight {
                return Err(conflict("Provisioning attempt already settled"));
            }
            record.status = next.clone();
            Ok((record.clone(), true))
        })
        .await
    }
}

fn validate_id(id: &str) -> XResult<()> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(XrpcError::bad("InvalidRequest", "Expected a 1–64 character alphanumeric operation ID"));
    }
    Ok(())
}

fn existing<'a>(records: &'a mut Reservations, id: &str) -> XResult<&'a mut Reservation> {
    records.get_mut(id).ok_or_else(|| XrpcError::bad("AgentReservationNotFound", "No such provisioning reservation"))
}

fn conflict(message: &str) -> XrpcError {
    XrpcError { status: StatusCode::CONFLICT, error: "AgentProvisioningConflict".into(), message: message.into() }
}

pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/xrpc/vlpds.agent.provision", post(provision))
        .route("/xrpc/vlpds.agent.getProvisioningStatus", get(provision_status))
        .route("/xrpc/vlpds.agent.listAgents", get(list_agents))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvisionInput {
    operation_id: String,
    handle: String,
    email: String,
    password: String,
    invite_code: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusInput {
    operation_id: String,
}

pub(super) async fn active_owner(app: &App, credentials: &Credentials) -> XResult<String> {
    let Credentials::Session { did } = credentials else {
        return Err(XrpcError::auth("A full account session is required"));
    };
    if internal::account_anywhere(app, did).await?.status.is_some() {
        return Err(XrpcError::auth("An active owner account is required"));
    }
    Ok(did.clone())
}

fn proof(owner: &str, id: &str, attempt: u64, handle: &str) -> String {
    let value = format!("agent-provisioning/v1\0{owner}\0{id}\0{attempt}\0{handle}");
    hex::encode(Sha256::digest(value))
}

fn response(id: &str, reservation: &Reservation) -> Json<Value> {
    let status = match reservation.status {
        Status::Reserved => "reserved",
        Status::InFlight => "pending",
        Status::Ready { .. } => "ready",
        Status::PlcUncertain => "needsReconciliation",
    };
    let mut result = json!({"operationId": id, "handle": reservation.handle, "status": status});
    if let Status::Ready { did } = &reservation.status {
        result["did"] = json!(did);
    }
    Json(result)
}

async fn reconcile(journal: &Journal<'_>, id: &str) -> XResult<Reservation> {
    let record = journal
        .get(id)
        .await?
        .ok_or_else(|| XrpcError::bad("AgentReservationNotFound", "No such provisioning reservation"))?;
    if record.status != Status::InFlight {
        return Ok(record);
    }

    let Some(did) = journal.app.resolve_handle(&record.handle).await? else {
        return Ok(record);
    };
    let account = match internal::account_anywhere(journal.app, &did).await {
        Ok(account) => account,
        Err(error) if error.error == "AccountNotFound" => return Ok(record),
        Err(error) => return Err(error),
    };
    let expected = proof(journal.owner, id, record.attempt, &record.handle);
    // The signup worker writes this marker with the initial repo head. A
    // handle claim or an unrelated account with the same handle is no proof.
    if account.did != did
        || account.handle != record.handle
        || account.extra.get(ACCOUNT_MARKER).and_then(Value::as_str) != Some(expected.as_str())
    {
        return Ok(record);
    }
    journal.settle(id, record.attempt, SignupOutcome::Created { did }).await
}

async fn provision_status(
    State(app): AppState,
    Auth(credentials): Auth,
    Query(input): Query<StatusInput>,
) -> XResult<Json<Value>> {
    let owner = active_owner(&app, &credentials).await?;
    let journal = Journal::new(&app, &owner);
    let record = journal
        .get(&input.operation_id)
        .await?
        .ok_or_else(|| XrpcError::bad("AgentReservationNotFound", "No such provisioning reservation"))?;
    Ok(response(&input.operation_id, &record))
}

async fn provision(
    State(app): AppState,
    Auth(credentials): Auth,
    Json(input): Json<ProvisionInput>,
) -> XResult<Json<Value>> {
    let owner = active_owner(&app, &credentials).await?;
    let journal = Journal::new(&app, &owner);
    let id = &input.operation_id;
    let handle = server::normalize_handle(&input.handle)?;
    journal.reserve(id, &handle, OWNER_QUOTA).await?;
    let Some(attempt) = journal.claim(id).await? else {
        return Ok(response(id, &reconcile(&journal, id).await?));
    };

    let marker = proof(&owner, id, attempt, &handle);
    let signup = server::CreateAccountIn {
        handle,
        email: Some(input.email),
        password: Some(input.password),
        invite_code: input.invite_code,
        ..Default::default()
    };
    let mut potentially_applied = false;
    match server::create_agent_account(&app, signup, &marker, &mut potentially_applied).await {
        Ok(account) => {
            super::cas::pause_point("agent_provisioning_before_settlement", &owner).await;
            let record = journal.settle(id, attempt, SignupOutcome::Created { did: account.did }).await?;
            Ok(response(id, &record))
        }
        Err(error) if !potentially_applied => {
            journal.settle(id, attempt, SignupOutcome::RejectedBeforeCreation).await?;
            Err(error)
        }
        Err(_) if app.plc.is_some() => {
            let record = journal.settle(id, attempt, SignupOutcome::PlcUncertain).await?;
            Ok(response(id, &record))
        }
        Err(_) => Ok(response(id, &reconcile(&journal, id).await?)),
    }
}

async fn list_agents(State(app): AppState, Auth(credentials): Auth) -> XResult<impl axum::response::IntoResponse> {
    let owner = active_owner(&app, &credentials).await?;
    let journal = Journal::new(&app, &owner);
    let mut agents = Vec::new();
    for (id, reservation) in journal.load().await?.1 {
        if let Some(agent) = verified_reservation(&journal, &id, &reservation).await {
            agents.push(agent);
        }
    }
    Ok(([(axum::http::header::CACHE_CONTROL, "no-store")], Json(json!({"agents": agents}))))
}

/// Check a binding already authorized by the caller's MCP grant. These
/// arguments must come from server-side grant state, never tool arguments.
pub async fn binding_is_verified(app: &App, owner: &str, agent: &str) -> bool {
    if !internal::account_anywhere(app, owner).await.is_ok_and(|a| a.status.is_none()) {
        return false;
    }
    let journal = Journal::new(app, owner);
    let Ok((_, records)) = journal.load().await else {
        return false;
    };
    for (id, reservation) in records {
        if matches!(&reservation.status, Status::Ready { did } if did == agent)
            && verified_reservation(&journal, &id, &reservation).await.is_some()
        {
            return true;
        }
    }
    false
}

async fn verified_reservation(journal: &Journal<'_>, id: &str, reservation: &Reservation) -> Option<Value> {
    let Status::Ready { did } = &reservation.status else {
        return None;
    };
    let expected = proof(journal.owner, id, reservation.attempt, &reservation.handle);
    let agent = internal::account_anywhere(journal.app, did).await.ok()?;
    if agent.status.is_some() || agent.extra.get(ACCOUNT_MARKER).and_then(Value::as_str) != Some(expected.as_str()) {
        return None;
    }
    let observation = super::agent_binding::observe(journal.app, did, journal.owner).await;
    if !matches!(observation.status, super::agent_binding::PairStatus::Verified { .. }) {
        return None;
    }
    Some(json!({"did": did, "handle": agent.handle}))
}
