# Activation diagnosis: run44933594641

## What is established

Exact source3c4fd31 passed fresh OFF preflight and provisioning at18:05:58Z and
18:06:01Z. Activation ran18:06:01–18:07:32Z (about91 seconds), failed, and
produced no readiness artifact. Otto never opened a prompt, logged in or called
the service. The first activation exception is not available in existing
sanitized evidence. No raw Actions logs were retrieved.

The distinct OFF transition passed18:07:47Z; verified binding cleanup and OFF
artifact upload passed18:07:51Z. The authenticated OFF artifact14718696593 has
ZIP SHA2565ea3715e42073206655cbc34ea63c0a0046ab26da443ff6474d0df3835d613e1.
Independent GET-only inspection44933972045 then passed. Artifact14718319506,
ZIP SHA256de5ac56667876f4d4c79fa88acd4a2870493739ed1ff16ce5e17a6cf6ca37bc9,
confirmed OFF/no lease, exactly23 baseline binding types, unchanged script ETag
88f6a917a64c75dda70dd40bb76cc74c8607790400fd50349095ec7fe615dc42,
qualified desired/current image2e254 running and health/UI200/Card404.
The resulting clean Worker is23ab139c-7cf7-423a-bbac-910dcbad8f92.
The exact token was revoked with owner tokenGet/active-list verification;
private custody and unused Otto output were removed. Only four ordinary Actions
secrets remain. Revocation and Card404 alone were not treated as cleanup proof.

## Why91 seconds does not identify the cause

| Boundary | Existing bound / behavior | What the duration can establish |
| --- | --- | --- |
| Fresh OFF reinspection | Individual GETs have15s timeouts; completed inspection must be <=30s | Could fail before publish; no substage evidence |
| Worker publish acknowledgement | Wrangler child timeout180s; structured session+deploy receipt required | Could fail sooner;91s is not the full child timeout |
| Applied Worker/config | Independent deployment/version GETs, exact acknowledged version and bindings | Acknowledgement alone is not applied-state proof |
| Runtime restart | Fresh status GET then POST timeout75s; Worker waits up to60s for confirmed process exit | A timeout/refusal plus other work can fit91s |
| Public readiness | At most20 inspections,19 sleeps of3s; each inspection may make bounded network calls | Fast pending Card404 alone contributes57s sleep; network work can bring total near91s |
| Final acceptance window | >=120s lease remaining before readiness receipt | No receipt means this gate was not proven |

The20-attempt readiness limit is not a60-second wall-clock promise. Do not infer
which boundary failed from elapsed job time or from the later successful OFF
transition. No new runtime bug is claimed from this evidence.

## Minimal additional evidence

Failure-only activation and OFF receipts now record fixed stage names/statuses
and locally measured monotonic durations. Stages distinguish private-state
load, lease/phase, fresh OFF reinspection, attempt persistence, publish ACK,
applied Worker/config validation, runtime restart, readiness and final state
persistence. Readiness retains at most20 fixed-code observations with check
boundary (runtime status, Card authority, Worker metadata/bindings, public
checks, final runtime status), attempt number and safe pending category.

No exception text, headers, provider bodies, credentials, private state or
caller strings are serialized. These diagnostics say readyForPilot=false and
cannot authorize retry. Successful activation uploads no extra diagnostic,
preserving Otto's single-readiness-artifact constraint. An OFF diagnostic is
uploaded only when its own step fails. The always-OFF/cleanup ordering, strict
version/config checks, restart-at-most-once rule, lease and polling limits are
unchanged. Diagnostic writes are best-effort and cannot block an OFF action or bypass a gate.
Setup failure or runner loss can leave no file or an incomplete
started stage; independent reconciliation remains required.

Fixtures distinguish a75s restart timeout (one POST only),20 pending Card
checks, publish failure, applied-version mismatch and OFF restart failure.
They assert no readiness authorization on failure and no binding cleanup before
verified OFF. No live run, token, deployment or provider probe was added to
obtain this evidence.

## Before Brittany needs the private Terminal

Credential-free fixtures and lint run before delivery. The existing GET-only
inspection can verify image, script, OFF/lease/bindings and public health without
Otto; candidate self-introspection can be checked separately under credential
approval. Neither validates the runtime mode transition or live readiness.
The same reviewed change narrowly updates the initial OFF pin from df75 to
the exact authenticated clean Worker23ab139c-7cf7-423a-bbac-910dcbad8f92; stale
and unrelated Worker IDs remain rejected. The existing qualification and all
other gates are unchanged. This baseline evidence does not approve a new window. The next authorized run must supply its own authenticated fresh
readiness artifact before any private prompt, and failure must stop without
retry. No claim of hosted Otto acceptance has been made.
