# Read-only update strategy projection

`cloudflare-strategy-projection.yml` uses the existing protected production
configuration secret only. It installs no packages, invokes no provider CLI,
and makes no Cloudflare requests. The helper emits only run identity, pinned
Wrangler version, strategy source, mode and maximum delay. Failures emit a
fixed message; neither input nor exception text is printed. The single receipt
is retained for one day and must be authenticated by run/head/artifact digest
before use. Dispatch requires separate approval; Git delivery is not dispatch.

The projection models Wrangler 4.158.0 precedence: CLI override, configuration,
then deferred with 300 seconds. The pilot ON/OFF publisher now supplies the
explicit `immediate` CLI override shared through `pilot-update-mode.mjs`.
The projection reports that selection without invoking the publisher; it is
not proof of a production deployment. Immediate mode discards maximum delay; deferred defaults an omitted
delay to 300. Unsupported or malformed strategy values refuse the projection.
This describes the current configuration input, not historical deployment
bytes or proof of the version executing in a particular Durable Object.

Cloudflare documents that the strategy is write-only: deployment GET responses
cannot recover it. Immediate adoption resets active objects across every class
exported by the Worker and may interrupt requests. A future policy change must
explicitly cover both ON and OFF publishes, since strategy does not carry over
between deployments. It must retain the existing guarded container restart,
lease, readiness, rollback and independent OFF/binding checks. This projection
does not change any such policy or make a pilot ready.

Reference: https://developers.cloudflare.com/durable-objects/deployments/durable-objects-code-updates/
