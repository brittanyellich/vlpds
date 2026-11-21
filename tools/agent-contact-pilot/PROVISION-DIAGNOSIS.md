# Provisioning diagnosis for run44927604980

## Established evidence and limits

The exact c66a54a workflow passed its local tests and fresh OFF preflight, then
failed `Provision only two pilot secrets while OFF`. Activation and readiness
upload were skipped; Otto never prompted, logged in or contacted the route.
The always-OFF and cleanup steps succeeded, but no OFF receipt was produced.
In the reviewed runner, a retained preflight phase exits those steps without
mutation/receipt. This is consistent with failure before persisting the
provision-attempt phase, including fresh reinspection or candidate introspection;
the job metadata does not identify the exact exception. Lost state is another
logical possibility. Do not describe a specific historical exception as proven.

Authenticated GET-only containment inspection44927774743 independently proved
unchanged clean Workerdf75d444-fd52-4314-b686-6461b792f4b4, script88f6...,23 exact
binding types, explicit OFF, no lease, qualified desired/current image2e254
running and health/UI200/Card404. The custodian verified exact token revocation
and private cleanup; the two temporary Actions secrets were removed. No pilot
retry or raw Actions log access was used for this diagnosis.

## Deterministic code defect and correction

Candidate self-introspection can slide idle expiry while its GET is in flight.
The old checker captured `now` before the request, then enforced expiresAt <=
that timestamp+900. A response one second later with its legitimate expiry at
completion+900 deterministically failed. Synthetic fixtures reproduce that
failure without a credential or network call. This is a confirmed defect and a
plausible historical cause, not proof of the failed run's first exception.

The checker now requires an injected completion clock, validates the response
against fresh completion time, and rejects backward/noninteger time, elapsed
requests beyond15 seconds and completion at/after the fixed pilot deadline.
The runtime passes its actual clock. The absolute expiry, issued-at freshness,
org/profile/scopes/ID binding and deadline+30 coverage checks are unchanged.
The lifecycle also rechecks the lease immediately before persisting any write
attempt. It does not extend the lease or retry a rejected token/API operation.

The owner also identified a custody file trailing newline. Our transfer used
`gh secret set` stdin, with installed gh2.103.0. Its exact tagged implementation
returns `bytes.TrimRight(body, "\r\n")` from the stdin path before encryption:
https://github.com/cli/cli/blob/v2.103.0/pkg/cmd/secret/set/set.go . Thus a custody
newline alone does not explain this supported transfer path. No stored secret
value or workflow credential was retrieved, and runtime whitespace is not
silently accepted by the checker.

## Sanitized failure stages

Provisioning records fixed stage names/statuses only: private-state load,
phase/lease, fresh OFF state, candidate introspection, attempt persistence,
two-binding transfer, provisioned-OFF verification and final persistence.
Candidate refusal subcodes distinguish input, request, HTTP/media, body, shape,
scope/time, exact metadata binding and acceptance-window checks. No exception
text, response body/header, bearer, private state or secret hash is copied.
Identity fields are strictly allowlisted. A receipt with readyForPilot=false
never authorizes a retry, prompt or mutation.

Only a failed path uploads `exp710-provision-diagnostic-${runId}` from the exact
sanitized file. Successful provisioning uploads no diagnostic artifact, leaving
Otto's existing single-ready-artifact constraint intact. Input/setup failure
before trace initialization may have no diagnostic file; upload warns rather
than copying another file. Runner loss may leave a `started` stage. These are
limits, not proof that a write did or did not happen. The write-attempt state,
independent provider reconciliation, lease and verified-OFF cleanup remain the
safety boundaries.

## Validation before an Otto operator is needed

1. Before PR delivery, run `npm test`, `npm run typecheck` and actionlint. The
   fixtures cover the clock boundary, strict caps/bindings, expiry during the
   request, diagnostic redaction and no CF write on introspection failure.
2. After reviewed merge and separate approval for a GET-only check, the existing
   `cloudflare-pilot-diagnostic.yml` can now validate this df75 baseline, image,
   source qualification, current Card key and public OFF checks using only the
   ordinary existing Actions secrets. No candidate token or Otto login is used;
   readyForPilot stays false. It has not been dispatched for this fix.
3. When a future candidate mint is separately authorized, the custodian can call
   this same `checkCandidateToken` helper with that candidate, exact normalized
   custodian metadata, intended bounded deadline and real start/completion
   clocks. The helper only GETs fixed `https://api.kody.codes/v1/tokens/current`;
   no CF credential, provisioning or Otto login is needed. Keep candidate input
   private and output only pass/fixed refusal code. This read can slide idle
   expiry but cannot move absolute expiry or the intended lease. A revoked token
   cannot validate a future live candidate; no token should be minted merely
   to make a fixture look live. This candidate check was not run live here.
4. The future approved single pilot still repeats fresh provider and same-value
   self-introspection gates immediately before writing. Only after its own
   authenticated fresh readiness receipt does Otto's private prompt open. A
   successful prior diagnostic cannot replace that receipt or a new approval.

This Actions-script-only change needs no runtime image/Worker rollout. Git
merge approval does not authorize credential operations or another pilot.
