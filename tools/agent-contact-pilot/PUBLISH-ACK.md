# Publish acknowledgement: local fix

The pinned Wrangler 4.158.0 emits `Current Version ID` through `logger.log`.
The pilot runner uses `WRANGLER_LOG=info`, which suppresses that level. A
successful publish can therefore fail the old stdout parser. This defect is
verified in installed source and credential-free local logging probes; it is
consistent with the failed production activation/OFF steps, but those runs'
exact first exceptions remain unproven without their rejected raw logs.

The runner now requests supported `WRANGLER_OUTPUT_FILE_PATH` ND-JSON and
passes the fixed `--name crate-pds`. Pinned Wrangler's deploy wrapper writes a
`type=deploy`, `version=1`, `worker_name`, `version_id` record after deployment.
The private, exclusive 0600 file must contain the pinned 4.158.0 session record followed by one bounded valid deploy record
with the exact worker name and a UUID version ID. Human console text is never
an acknowledgement. Subprocess failure/timeout, missing, malformed or multiple
records fail closed without automatic retry or captured-output disclosure.
The enclosing runner removes the private directory in `finally`.

This is an acknowledgement, not proof of production state. Existing lifecycle
checks independently require authoritative active Worker metadata to match the
returned ID and exact config before restarting. Ambiguous activation cannot
restart; a distinct verified OFF operation is still permitted. Ambiguous OFF
cannot authorize restart or binding deletion. The runtime lease remains intact.

Supported interface references:
- https://developers.cloudflare.com/workers/wrangler/system-environment-variables/
- https://developers.cloudflare.com/changelog/post/2025-11-03-wrangler-output-file/

Validation: `npm test` and `npm run typecheck` in `deploy/cloudflare`.
Synthetic tests cover missing human markers, invalid/duplicate receipts,
post-write process failure/timeout, and activation/OFF ambiguity sequencing.
No live publish or successful provider round trip has been performed for this
fix. No credentials, settings, image, Worker source or lease changes are needed
in this local diff. Git delivery and a new pilot require separate approval.
A future pilot must explicitly qualify its current OFF baseline after cleanup;
this change does not relax the original hard-coded baseline or reuse old readiness.

An actual credential-free pinned CLI dry run confirmed the session/deploy ND-JSON sequence at info log level. Its deploy record has no version ID and is deliberately rejected; this is not evidence of a live publish.
