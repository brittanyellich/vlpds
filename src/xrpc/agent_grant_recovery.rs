//! Owner-partition state for a trusted OAuth integration. No provider calls
//! or authorization codes are stored here.

pub mod runner;

use super::agent_dispatch::{self, Binding, Grant, Row};
use super::agent_provisioning::active_owner;
use super::authn::Credentials;
use super::cas::{Cond, Op};
use super::{App, XResult, XrpcError};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Request {
    pub issuer: String,
    pub resource: String,
    pub client: String,
    pub request_digest: [u8; 32],
    pub binding: Binding,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum State {
    Reserved,
    Issuing,
    Abandoned,
    Bound { grant: String },
    Cleanup { grant: String, issuer_done: bool, upstream_done: bool },
    Closed { grant: Option<String> },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Intent {
    pub request: Request,
    pub correlation: String,
    pub state: State,
}

/// The caller obtains this only from the trusted issuer's completion or
/// reconciliation API, checking the configured issuer, owner, client and resource.
pub struct Observation<'a> {
    pub grant: Grant<'a>,
    pub client: &'a str,
    pub correlation: &'a str,
}

#[derive(Clone, Copy)]
pub enum CleanupTarget {
    Issuer,
    Upstream,
}

/// Construct per authenticated request. A trusted background recovery runner
/// with its own authority is a separate integration boundary.
pub struct Recovery<'a> {
    app: &'a App,
    owner: String,
}

fn refused() -> XrpcError {
    XrpcError::bad("GrantRecoveryConflict", "Grant recovery evidence or state does not match the operation")
}

fn encode(intent: &Intent) -> XResult<Bytes> {
    serde_json::to_vec(intent).map(Bytes::from).map_err(XrpcError::from_err)
}

fn operation_row(id: &str) -> XResult<String> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
        return Err(refused());
    }
    Ok(format!("agent-grant-recovery/v1/{id}"))
}

fn cleanup(grant: &str) -> State {
    State::Cleanup { grant: grant.into(), issuer_done: false, upstream_done: false }
}

enum GrantWrite {
    Approve { row: String, binding: Binding },
    Revoke { row: String, binding: Binding },
}

impl<'a> Recovery<'a> {
    pub async fn for_owner(app: &'a App, credentials: &Credentials, owner: &str) -> XResult<Self> {
        let recovery = Self::for_session(app, credentials).await?;
        if recovery.owner() != owner {
            return Err(XrpcError::auth("Recovery owner does not match the signed-in account"));
        }
        Ok(recovery)
    }

    /// Derive the owner from a verified PDS session for consent front ends.
    pub async fn for_session(app: &'a App, credentials: &Credentials) -> XResult<Self> {
        Ok(Self { app, owner: active_owner(app, credentials).await? })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub async fn reserve(&self, operation: &str, request: Request) -> XResult<Intent> {
        let row = operation_row(operation)?;
        let grant = self.grant(&request, operation);
        grant.row()?;
        if request.client.is_empty() || request.client.len() > 2048 || request.client.chars().any(char::is_control) {
            return Err(refused());
        }
        if let Some(existing) = self.get(operation).await? {
            return if existing.request == request { Ok(existing) } else { Err(refused()) };
        }
        agent_dispatch::verify_binding(self.app, &self.owner, &request.binding).await?;
        let intent = Intent { request, correlation: crate::space::token::new_jti(), state: State::Reserved };
        let written = self
            .app
            .private_cas(&self.owner, vec![Cond::eq(&row, None)], vec![Op::put(&row, Some(encode(&intent)?))])
            .await?;
        if written.applied {
            return Ok(intent);
        }
        self.get(operation).await?.filter(|existing| existing.request == intent.request).ok_or_else(refused)
    }

    /// Reserve the consent and claim its one issuer call. The returned
    /// correlation must be attached to the issuer's durable grant metadata.
    pub async fn begin_issuance(&self, operation: &str, request: Request) -> XResult<Option<String>> {
        self.reserve(operation, request).await?;
        self.claim(operation).await
    }

    pub async fn get(&self, operation: &str) -> XResult<Option<Intent>> {
        self.app
            .get_private(&self.owner, &operation_row(operation)?)
            .await?
            .map(|raw| serde_json::from_slice(&raw).map_err(XrpcError::from_err))
            .transpose()
    }

    /// Only the CAS winner can call the issuer. An unresolved claim is never
    /// eligible for a second issuance, including after a restart.
    pub async fn claim(&self, operation: &str) -> XResult<Option<String>> {
        self.change(operation, |intent| {
            if intent.state != State::Reserved {
                return Ok((None, None));
            }
            intent.state = State::Issuing;
            Ok((Some(intent.correlation.clone()), None))
        })
        .await
    }

    /// True only for the caller that just bound an issuer response it still
    /// holds. Only that caller may return the redirect to the owner.
    pub async fn issued(&self, operation: &str, observed: &Observation<'_>) -> XResult<bool> {
        self.change(operation, |intent| {
            self.check_observation(intent, observed)?;
            match &intent.state {
                State::Issuing => {}
                State::Bound { grant } if grant == observed.grant.id => return Ok((false, None)),
                _ => return Err(refused()),
            }
            intent.state = State::Bound { grant: observed.grant.id.into() };
            Ok((
                true,
                Some(GrantWrite::Approve { row: observed.grant.row()?, binding: intent.request.binding.clone() }),
            ))
        })
        .await
    }

    /// Recover a grant for which the redirect is unavailable. It can only be
    /// tombstoned and cleaned up. A retry needs a new owner consent operation.
    /// Call only after the integration has established that the response is lost
    /// or the owner abandoned it. Temporary issuer lookup failure is no evidence.
    pub async fn reconcile_lost_redirect(&self, operation: &str, observed: &Observation<'_>) -> XResult<()> {
        self.change(operation, |intent| {
            self.check_observation(intent, observed)?;
            match &intent.state {
                State::Issuing | State::Abandoned => {}
                State::Bound { grant } if grant == observed.grant.id => {}
                State::Cleanup { grant, .. } | State::Closed { grant: Some(grant) } if grant == observed.grant.id => {
                    return Ok(((), None));
                }
                _ => return Err(refused()),
            }
            intent.state = cleanup(observed.grant.id);
            Ok(((), Some(GrantWrite::Revoke { row: observed.grant.row()?, binding: intent.request.binding.clone() })))
        })
        .await
    }

    /// Persist the tombstone and cleanup task in the same owner transaction.
    /// An in-flight issue with no known ID retains its correlation for recovery.
    pub async fn cancel(&self, operation: &str) -> XResult<()> {
        self.change(operation, |intent| {
            let write = match &intent.state {
                State::Reserved => {
                    intent.state = State::Closed { grant: None };
                    None
                }
                State::Issuing => {
                    intent.state = State::Abandoned;
                    None
                }
                State::Bound { grant } => {
                    let row = self.grant(&intent.request, grant).row()?;
                    intent.state = cleanup(grant);
                    Some(GrantWrite::Revoke { row, binding: intent.request.binding.clone() })
                }
                _ => None,
            };
            Ok(((), write))
        })
        .await
    }

    /// Record an affirmative result from an idempotent cleanup call. Retried
    /// or ambiguous calls do not advance the other cleanup target.
    pub async fn acknowledge(&self, operation: &str, grant_id: &str, target: CleanupTarget) -> XResult<()> {
        self.change(operation, |intent| {
            match &mut intent.state {
                State::Cleanup { grant, issuer_done, upstream_done } if grant == grant_id => {
                    match target {
                        CleanupTarget::Issuer => *issuer_done = true,
                        CleanupTarget::Upstream => *upstream_done = true,
                    }
                    if *issuer_done && *upstream_done {
                        intent.state = State::Closed { grant: Some(grant.clone()) };
                    }
                }
                State::Closed { grant: Some(grant) } if grant == grant_id => {}
                _ => return Err(refused()),
            }
            Ok(((), None))
        })
        .await
    }

    fn grant<'b>(&'b self, request: &'b Request, id: &'b str) -> Grant<'b> {
        Grant { issuer: &request.issuer, resource: &request.resource, id, owner: &self.owner }
    }

    fn check_observation(&self, intent: &Intent, observed: &Observation<'_>) -> XResult<()> {
        let expected = self.grant(&intent.request, observed.grant.id);
        if observed.grant.owner != expected.owner
            || observed.grant.issuer != expected.issuer
            || observed.grant.resource != expected.resource
            || observed.client != intent.request.client
            || observed.correlation != intent.correlation
        {
            return Err(refused());
        }
        Ok(())
    }

    async fn change<T>(
        &self,
        operation: &str,
        update: impl Fn(&mut Intent) -> XResult<(T, Option<GrantWrite>)>,
    ) -> XResult<T> {
        let row = operation_row(operation)?;
        for _ in 0..8 {
            let old = self.app.get_private(&self.owner, &row).await?.ok_or_else(refused)?;
            let mut intent = serde_json::from_slice(&old).map_err(XrpcError::from_err)?;
            let (result, grant) = update(&mut intent)?;
            let next = encode(&intent)?;
            if next == old && grant.is_none() {
                return Ok(result);
            }
            if intent.state == State::Issuing {
                // A reserved intent can outlive its original binding check.
                agent_dispatch::verify_binding(self.app, &self.owner, &intent.request.binding).await?;
            }
            let mut conditions = vec![Cond::eq(&row, Some(old))];
            let mut writes = vec![Op::put(&row, Some(next))];
            if let Some(write) = grant {
                let (key, binding, revoke) = match write {
                    GrantWrite::Approve { row, binding } => (row, binding, false),
                    GrantWrite::Revoke { row, binding } => (row, binding, true),
                };
                let current = self.app.get_private(&self.owner, &key).await?;
                let next = if revoke { Row::Revoked } else { Row::Approved(binding.clone()) };
                if let Some(bytes) = &current {
                    let row: Row = serde_json::from_slice(bytes).map_err(XrpcError::from_err)?;
                    if !revoke || (row != Row::Approved(binding.clone()) && row != Row::Revoked) {
                        return Err(refused());
                    }
                }
                if !revoke {
                    agent_dispatch::verify_binding(self.app, &self.owner, &binding).await?;
                }
                conditions.push(Cond::eq(&key, current));
                writes.push(Op::put(key, Some(agent_dispatch::encode(&next)?)));
            }
            if self.app.private_cas(&self.owner, conditions, writes).await?.applied {
                return Ok(result);
            }
        }
        Err(refused())
    }
}
