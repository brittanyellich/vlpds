---
title: Owner self-service agent provisioning
section: Spaces
order: 209
status: draft
summary: An owner-scoped provisioning lifecycle exercised against the existing vlPDS account and repo APIs.
---

```hero
diagram:
  caption: "The owner starts an operation. The PDS reserves it, runs regular signup checks, and records the agent account."
  nodes:
    - { id: owner, label: Owner session, at: [0, 0], size: [12, 3], tone: blue }
    - { id: journal, label: Private reservation, at: [15, 0], size: [14, 3], tone: violet }
    - { id: signup, label: PDS signup, at: [32, 0], size: [12, 3], tone: amber }
  edges:
    - owner -> journal
    - journal -> signup
facts:
  - { value: "1", label: reservation slot per owner }
  - { value: Private, label: owner journal }
  - { value: "Stop", label: when PLC outcome is uncertain }
```

### Owner-facing lifecycle

Use the signed-in owner's DID from the PDS session. The owner supplies an operation ID to start provisioning or retry an existing operation. Store one private reservation per owner DID and operation ID. Check the owner's quota when creating a reservation. Retrying a known operation uses its existing reservation, including when the owner is at quota.

| State | Behavior |
| --- | --- |
| Reserved | Allocate stable signup inputs before calling account creation. Count the reservation towards quota. |
| Pending | Record that signup may have been submitted. A retry reconciles the outcome before submitting again with the same reserved inputs. |
| Ready | Return the existing agent DID and handle. An owner-only list returns ready agents, and an owner-only status lookup reports pending or ready for an operation. |

The fixture reconciles a lost response by signing in with a generated operation-specific password. A matching handle alone is insufficient to adopt an account. If the credential does not authenticate, account creation still has to satisfy handle and email uniqueness. A successful signup or reconciliation returns the agent DID and handle, while signup credentials and session tokens stay inside the fixture.

### Account policy

The fixture calls the regular `com.atproto.server.createAccount` endpoint. The same account policy applies to normal signup and delegated agent provisioning, including the invite requirement, email validation and uniqueness, service-handle policy, DID issuance, and repository creation. An owner session authorizes the provisioning operation. Existing `createAccount` service JWT support serves imported DIDs and does not establish owner-to-agent relationships.

The fixture uses the existing full-account-session gate and derives the owner DID from `getSession`. It starts an invite-required test PDS, creates disposable accounts with synthetic email addresses, and passes a one-use invite into agent signup. Setup creates those invitations through the existing admin API. Provisioning itself receives an invite and uses the regular signup route. If an invite is missing or invalid, the request may resume with a new valid invite under the same operation ID.

### Verified locally

Run `cargo test --offline --locked --test all owner_agent_provisioning_retries_and_isolation`. The fixture checks unauthenticated access, invite enforcement, per-owner quota, owner-only status and listing, recovery after a committed signup response is lost, and two concurrent retries returning that original DID and handle. It verifies that the resulting agent has an initial repository commit.

The coordinator and journal are test-only. Reopening the coordinator in the test keeps the same in-memory journal and PDS; it does not establish process-restart durability. The PDS signup pipeline creates the actual disposable account and repo.

### Durable reservation primitive

The internal `xrpc::agent_provisioning::Journal` stores a bounded private row on the owner's existing PDS partition. A CAS update reserves the operation and charges quota together. The operation ID and handle remain stable on retry. Quota includes reserved, in-flight, ready, and uncertain entries. The row holds only the handle, status, attempt number, and confirmed agent DID when available.

A caller may submit signup only after it wins the durable claim and receives its attempt number. A report must match that attempt. A confirmed rejection before any identity or account was created frees the same reservation for a new attempt. A confirmed account and repo let the caller record the result. Repeating the same report is idempotent, and older attempt numbers cannot alter a later one.

A timeout, crash, or lost claim acknowledgement leaves an in-flight operation blocked for reconciliation. If PLC may have applied genesis or cleanup is unconfirmed, mark the attempt `PlcUncertain`. That state holds quota and blocks automated retry. The journal does not mint identities or infer whether a PDS or PLC error is safe to retry.

Run `cargo test --offline --locked --test all owner_agent_reservations_are_atomic_and_survive_restart`. The test restarts a PDS node against the same disposable object store and verifies concurrent quota and claim enforcement, owner partition isolation, stale-attempt rejection, and the PLC stop recorded from a simulated outcome. It performs no PLC calls.

### Authenticated XRPC

`POST /xrpc/vlpds.agent.provision` takes `operationId`, `handle`, `email`, `password`, and an optional `inviteCode`. It derives the owner from an active full PDS account session and applies a one-slot owner quota. It uses regular signup checks and shares the signup IP rate-limit bucket. The response includes the operation ID, handle, and status, plus the agent DID once ready. Credentials and owner identity are absent from the returned agent data.

`GET /xrpc/vlpds.agent.getProvisioningStatus?operationId=…` reads an operation in the caller's owner partition. Repeat the POST with the same operation ID and handle to recover a lost response. Signup writes a private proof of the owner, operation, handle, and attempt alongside the agent account and the initial repo head. A retry checks the existing PDS account for that proof before completing the journal. A handle claim or an account created by a different operation cannot satisfy recovery.

The endpoint can complete ordinary signup synchronously. A failure before any repo or PLC submission returns the signup error and leaves the same reservation available for retry. If a repo submission might have succeeded, an unverified operation stays `pending`. If an error follows possible PLC submission, the endpoint records `needsReconciliation`. Neither path submits another signup. Reconciliation after a partial PLC failure still requires a separate lifecycle step and verified identity evidence.

The endpoint test cancels the request after signup commits and before the journal is settled. Concurrent retries recover the original DID. It also checks the invite requirement, quota, cross-owner status and recovery, and a simulated PLC stop. Run `cargo test --offline --locked --test all owner_agent_endpoint_recovers_a_lost_signup_response`.

### Remaining production work

Define a resolution path for parked operations. For PLC, durably record signed genesis provenance before an external submit so a reconciler can verify the exact DID and repo across partial failure. Decide how to fence operations when an owner account is disabled or deleted and when to expire an abandoned reservation. The local endpoint does not free quota for unknown outcomes.

An owner supplies the email and password for the new account under the existing signup policy. A production UI, secure agent credential bootstrap, and provider OAuth consent remain separate slices. The [private agent list](agent-binding.md#private-discovery) requires a verified principal binding. Ordinary ATProto identity and repo visibility apply to a created account. The provisioning journal and proof are private PDS state.
