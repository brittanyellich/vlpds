//! A single reconciliation and cleanup pass. The integration schedules
//! retries and supplies an independently authenticated provider adapter.

use super::{refused, CleanupTarget, Grant, Observation, Recovery, Request, State, XResult};
use std::future::Future;

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Pending,
    Found(IssuedGrant),
}

#[derive(Debug, PartialEq, Eq)]
pub struct IssuedGrant {
    pub owner: String,
    pub issuer: String,
    pub resource: String,
    pub client: String,
    pub correlation: String,
    pub id: String,
}

impl IssuedGrant {
    fn observation(&self) -> Observation<'_> {
        Observation {
            grant: Grant { issuer: &self.issuer, resource: &self.resource, id: &self.id, owner: &self.owner },
            client: &self.client,
            correlation: &self.correlation,
        }
    }
}

/// Only an affirmative response permits a durable acknowledgment. In
/// particular a stale absence does not constitute completion.
#[derive(PartialEq, Eq)]
pub enum CleanupOutcome {
    Complete,
    Retry,
}

/// Implementations must pin the issuer and translate the owner to a verified
/// provider subject. A bounded lookup returns Pending on absence, uncertainty,
/// or an exhausted page budget. Cleanup calls must be idempotent.
pub trait Provider {
    fn lookup(&self, owner: &str, request: &Request, correlation: &str)
        -> impl Future<Output = XResult<Lookup>> + Send;

    fn cleanup(&self, grant: Grant<'_>, target: CleanupTarget) -> impl Future<Output = CleanupOutcome> + Send;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    WaitingForIssuer,
    CleanupPending,
    Closed,
}

/// Request cancellation or confirm that the original redirect is unrecoverable
/// before calling this pass. It never issues a grant or releases a redirect.
pub async fn resume_abandoned(recovery: &Recovery<'_>, operation: &str, provider: &impl Provider) -> XResult<Progress> {
    let intent = recovery.get(operation).await?.ok_or_else(refused)?;
    match intent.state {
        State::Abandoned => {
            let Lookup::Found(grant) = provider.lookup(&recovery.owner, &intent.request, &intent.correlation).await?
            else {
                return Ok(Progress::WaitingForIssuer);
            };
            recovery.reconcile_lost_redirect(operation, &grant.observation()).await?;
        }
        State::Cleanup { .. } => {}
        State::Closed { .. } => return Ok(Progress::Closed),
        // The live issuance/redirect path must explicitly abandon its attempt.
        State::Reserved | State::Issuing | State::Bound { .. } => return Err(refused()),
    }
    let intent = recovery.get(operation).await?.ok_or_else(refused)?;
    let State::Cleanup { grant, issuer_done, upstream_done } = &intent.state else {
        return if matches!(intent.state, State::Closed { .. }) { Ok(Progress::Closed) } else { Err(refused()) };
    };
    let grant_key = recovery.grant(&intent.request, grant);
    for (target, done) in [(CleanupTarget::Issuer, *issuer_done), (CleanupTarget::Upstream, *upstream_done)] {
        if !done && provider.cleanup(grant_key, target).await == CleanupOutcome::Complete {
            recovery.acknowledge(operation, grant, target).await?;
        }
    }
    let latest = recovery.get(operation).await?.ok_or_else(refused)?;
    Ok(if matches!(latest.state, State::Closed { .. }) { Progress::Closed } else { Progress::CleanupPending })
}
