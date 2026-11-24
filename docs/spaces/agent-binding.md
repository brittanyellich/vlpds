---
title: Owner-approved ident.link binding
section: Spaces
order: 210
status: draft
summary: Two separate approvals and a signed repository proof for an agent's declared principal.
---

The [2026-10-22 ident.link draft](https://github.com/bluesky-social/ident.link/blob/41af2b3/docs/index.md) defines two public statements. The agent declares `https://ident.link/agent-of/<principal-did>` in its DID document's `alsoKnownAs`. The principal creates a `link.ident.endorsement` record at the agent DID key in its own repository. The record value contains `$type: "link.ident.endorsement"` and `agent: "<agent-did>"`. Each pair is verified independently. [Endorsement lexicon](https://github.com/bluesky-social/ident.link/blob/41af2b3/lexicons/link/ident/endorsement.json)

The existing operator helper uses these PDS capabilities:

- The principal approves a create-only `atproto repo:link.ident.endorsement?action=create` grant. The helper uses `createRecord` and preserves any existing matching record.
- The agent operator separately approves `atproto identity:*`. It requests the identity email with a bodyless `requestPlcOperationSignature` call and uses the confirmation to sign the reviewed `alsoKnownAs` change. It checks the signed plan against the original keys, aliases, and services, checks the original PLC data again before submission, and reads back the result. Keep this grant and email access out of the agent runtime.
- A verifier authenticates the endorsement against the principal DID document's signing key using the signed `com.atproto.sync.getRecord` proof. It checks the record key and value, the separately read record, and the same repository head before and after the read. Missing, invalid, or unavailable evidence leaves the relationship unconfirmed.

Run `cargo test --offline --locked --test all ident_link_binding`. The test uses distinct synthetic account sessions and DPoP keys, the loopback PDS, the dev mail spool, and a mock PLC directory. The reusable verifier accepts an expected agent and principal pair. The existing rollout verifier still supplies its fixed pair.

The test exercises a principal endorsement before the agent declares, successful verification after both sides approve, and a second owner whose signed endorsement cannot substitute for the declared principal's. Removing either party's statement makes the binding unavailable. The test revokes the temporary OAuth grants separately and checks that the elevated grant can no longer request identity mail.

### Current pair observation

`xrpc::agent_binding::observe(app, agent, principal)` takes an expected pair and returns the pair, the local completion time, and a typed status. `Verified` carries the signed commit and record CIDs. `SignedAbsent` carries the commit CID authenticating absence of the endorsement while the declaration is present. `Undeclared` means stable, valid PLC data lacks the reciprocal declaration. `Unavailable` covers changed heads or DID data, inactive or malformed identity data, lookup failures, proof failures, and timeout. The local time records this observation and grants no freshness lease.

The adapter uses the PDS's configured PLC directory and a principal repo hosted on the current node. It accepts no provisioning marker, caller-provided evidence, OAuth consent, or private authorization state. The existing `agent_endorsement::verify_pair` remains the pure verifier for a separately trusted snapshot. For a principal hosted elsewhere, the consumer needs its own trusted evidence retrieval. A markerless existing pair can verify at the proof layer. EXP-711 discovery additionally requires the authenticated owner's ready journal entry and matching original signup marker.

### Private discovery

`GET /xrpc/vlpds.agent.listAgents` takes an active full PDS account session and returns `{"agents":[{"did":"…","handle":"…"}]}` with `Cache-Control: no-store`. It reads only the authenticated owner's private provisioning journal. A ready reservation enters the list after the PDS confirms its original signup marker, checks the current agent account, and verifies both ident.link statements against a fresh PLC and repository proof. A provisioning status of `ready` describes account creation and can precede binding approval. Lookup failure, changed evidence, missing statements, and an inactive agent all omit the agent from discovery.

The route currently verifies hosted `did:plc` accounts through this PDS's configured directory. Fresh reads omit a binding after either side has removed its statement. The check bounds a single observation and cannot guarantee that the evidence remains current after the response. The disposable integration verifies two owners with real provisioned accounts, each seeing only their own confirmed agent and retaining independent access when the other binding is revoked.
