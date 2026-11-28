//! Durable single-writer coordination for a sealed Spaces OAuth credential.
//!
//! A claim removes the usable envelope before any upstream refresh. An
//! interrupted claim stays blocked until verified owner re-consent.

use crate::xrpc::agent_dispatch::Binding;
use crate::xrpc::agent_grant_recovery::runner::CleanupOutcome;
use crate::xrpc::cas::{Cond, Op};
use crate::xrpc::{App, XResult, XrpcError};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;

#[derive(Serialize, Deserialize)]
enum State {
    Ready { grant: Grant, envelope: Vec<u8> },
    Rotating { grant: Grant, claim: String },
}

/// Immutable, issuer-verified identity for one upstream authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub issuer: String,
    pub client: String,
    pub id: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retirement {
    pub owner: String,
    pub grant: Grant,
}

pub struct Blocked {
    marker: Bytes,
    grant: Grant,
    claim: String,
}

impl Blocked {
    pub(super) fn grant(&self) -> &Grant {
        &self.grant
    }
}

pub struct Rotation<'a> {
    app: &'a App,
    owner: &'a str,
    row: String,
}

pub struct Claim {
    row: String,
    owner: String,
    marker: Bytes,
    grant: Grant,
    pub envelope: Vec<u8>,
}

impl Claim {
    pub(super) fn grant(&self) -> &Grant {
        &self.grant
    }
}

impl<'a> Rotation<'a> {
    /// Use the verified owner and server-selected binding as the storage key.
    pub fn new(app: &'a App, owner: &'a str, binding: &Binding) -> XResult<Self> {
        let binding = serde_json::to_vec(binding).map_err(XrpcError::from_err)?;
        let row = format!("agent-chat-rotation/v1/{}", hex::encode(Sha256::digest(binding)));
        Ok(Self { app, owner, row })
    }

    pub(super) async fn ready_grant(&self) -> XResult<Option<Grant>> {
        let Some(current) = self.app.get_private(self.owner, &self.row).await? else {
            return Ok(None);
        };
        match serde_json::from_slice(&current).map_err(XrpcError::from_err)? {
            State::Ready { grant, .. } => Ok(Some(grant)),
            State::Rotating { .. } => Ok(None),
        }
    }

    pub(super) async fn ready_for_replacement(&self) -> XResult<Option<Blocked>> {
        let Some(marker) = self.app.get_private(self.owner, &self.row).await? else { return Ok(None) };
        let State::Ready { grant, .. } = serde_json::from_slice(&marker).map_err(XrpcError::from_err)? else {
            return Ok(None);
        };
        Ok(Some(Blocked { marker, grant, claim: crate::space::token::new_jti() }))
    }

    pub async fn install(&self, grant: Grant, envelope: Vec<u8>) -> XResult<bool> {
        self.replace(None, State::Ready { grant, envelope }).await
    }

    pub async fn claim(&self) -> XResult<Option<Claim>> {
        let Some(current) = self.app.get_private(self.owner, &self.row).await? else {
            return Ok(None);
        };
        let State::Ready { grant, envelope } = serde_json::from_slice(&current).map_err(XrpcError::from_err)? else {
            return Ok(None);
        };
        let marker = encode(&State::Rotating { grant: grant.clone(), claim: crate::space::token::new_jti() })?;
        if !self.write(Some(current), marker.clone()).await? {
            return Ok(None);
        }
        Ok(Some(Claim { row: self.row.clone(), owner: self.owner.into(), marker, grant, envelope }))
    }

    /// A late response can only replace the exact claim that authorized it.
    pub async fn complete(&self, claim: Claim, envelope: Vec<u8>) -> XResult<bool> {
        if claim.owner != self.owner || claim.row != self.row {
            return Ok(false);
        }
        self.replace(Some(claim.marker), State::Ready { grant: claim.grant, envelope }).await
    }

    pub async fn blocked(&self) -> XResult<Option<Blocked>> {
        let Some(marker) = self.app.get_private(self.owner, &self.row).await? else {
            return Ok(None);
        };
        match serde_json::from_slice(&marker).map_err(XrpcError::from_err)? {
            State::Rotating { grant, claim } => Ok(Some(Blocked { marker, grant, claim })),
            State::Ready { .. } => Ok(None),
        }
    }

    /// The caller verifies fresh owner consent and the replacement against the
    /// same binding. The compare-and-swap fences old refresh responses.
    pub async fn replace_blocked(&self, blocked: Blocked, grant: Grant, envelope: Vec<u8>) -> XResult<Option<String>> {
        if grant.client != blocked.grant.client {
            return Ok(None);
        }
        self.replace_after_consent(blocked, grant, envelope).await
    }

    pub(super) async fn replace_after_consent(
        &self,
        blocked: Blocked,
        grant: Grant,
        envelope: Vec<u8>,
    ) -> XResult<Option<String>> {
        if grant.issuer != blocked.grant.issuer || grant.id == blocked.grant.id {
            return Ok(None);
        }
        let cleanup = self.retirement_row(&blocked.claim);
        let retirement = Retirement { owner: self.owner.into(), grant: blocked.grant };
        let retired = Bytes::from(serde_json::to_vec(&retirement).map_err(XrpcError::from_err)?);
        let written = self
            .app
            .private_cas(
                self.owner,
                vec![Cond::eq(&self.row, Some(blocked.marker)), Cond::eq(&cleanup, None)],
                vec![
                    Op::put(&self.row, Some(encode(&State::Ready { grant, envelope })?)),
                    Op::put(cleanup, Some(retired)),
                ],
            )
            .await?;
        Ok(written.applied.then_some(blocked.claim))
    }

    /// The supplied adapter must retire the exact immutable upstream grant
    /// and treat confirmed absence as success. Errors leave the row queued.
    pub async fn retire<F, Fut>(&self, id: &str, cleanup: F) -> XResult<CleanupOutcome>
    where
        F: FnOnce(Retirement) -> Fut,
        Fut: Future<Output = CleanupOutcome>,
    {
        let row = self.retirement_row(id);
        let Some(raw) = self.app.get_private(self.owner, &row).await? else {
            return Ok(CleanupOutcome::Complete);
        };
        let retirement = serde_json::from_slice(&raw).map_err(XrpcError::from_err)?;
        if cleanup(retirement).await == CleanupOutcome::Retry {
            return Ok(CleanupOutcome::Retry);
        }
        self.app.private_cas(self.owner, vec![Cond::eq(&row, Some(raw))], vec![Op::put(row, None)]).await?;
        Ok(CleanupOutcome::Complete)
    }

    /// Retire a queued grant issued by this PDS. This adapter operates only
    /// on trusted owner-partition retirement records and uses no owner token.
    pub async fn retire_local(&self, id: &str) -> XResult<CleanupOutcome> {
        self.retire(id, |retirement| async move {
            let grant = retirement.grant;
            if retirement.owner != self.owner || grant.issuer != self.app.config.public_url {
                return CleanupOutcome::Retry;
            }
            use crate::oauth::store::{delete_session, get_session};
            match get_session(self.app, self.owner, &grant.id).await {
                Ok(None) => CleanupOutcome::Complete,
                Ok(Some(session)) if session.client_id == grant.client => {
                    match delete_session(self.app, self.owner, &grant.id).await {
                        Ok(()) => CleanupOutcome::Complete,
                        Err(_) => CleanupOutcome::Retry,
                    }
                }
                _ => CleanupOutcome::Retry,
            }
        })
        .await
    }

    /// Run one bounded cleanup pass for a configured binding. Queue rows
    /// survive a restart and are only removed after confirmed retirement.
    pub async fn drain_local_retirements(&self, limit: usize) -> XResult<usize> {
        let prefix = self.retirement_row("");
        let pending = crate::xrpc::internal::scan_private_anywhere(self.app, self.owner, &prefix).await?;
        let mut completed = 0;
        for (row, _) in pending.into_iter().take(limit) {
            if let Some(id) = row.strip_prefix(&prefix) {
                if self.retire_local(id).await? == CleanupOutcome::Complete {
                    completed += 1;
                }
            }
        }
        Ok(completed)
    }

    fn retirement_row(&self, id: &str) -> String {
        format!("{}/retire/{id}", self.row)
    }

    async fn replace(&self, expected: Option<Bytes>, state: State) -> XResult<bool> {
        self.write(expected, encode(&state)?).await
    }

    async fn write(&self, expected: Option<Bytes>, value: Bytes) -> XResult<bool> {
        Ok(self
            .app
            .private_cas(self.owner, vec![Cond::eq(&self.row, expected)], vec![Op::put(&self.row, Some(value))])
            .await?
            .applied)
    }
}

fn encode(state: &State) -> XResult<Bytes> {
    serde_json::to_vec(state).map(Bytes::from).map_err(XrpcError::from_err)
}
