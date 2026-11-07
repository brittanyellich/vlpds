# pds.crate.social on Cloudflare Containers

This deployment targets one always-running PDS with Spaces enabled, backed by R2.
It is experimental until the live acceptance checks below pass. `ENABLED=false`
keeps the deployment from starting a container before preflight is complete.

## Current deployment (November 6, 2026)

The live deployment uses the Git-ignored `.wrangler/deployment.json`, with
`ENABLED=true`, an operator SSH public key, and the CI-tested image pinned to:

`registry.cloudflare.com/adf874842159d9b3330e115c709d28fd/vlpds@sha256:5a7f2728d0304ff391276ad7c43fa1a16fd92bf59d31eec18ed9c1bc0deda63b`

The image was exported by CI run `42261323694` from commit `719a52e`.
For Worker-only changes, deploy with
`npx wrangler deploy --config .wrangler/deployment.json` from this directory.
The default `wrangler.jsonc` remains a disabled build-from-source template;
using it directly would disable the live service and omit operator SSH access.
Never upload `.dev.vars` wholesale: it includes the local-only DNS token.
The recovery private key is in the separate private backup and never uploaded.

The private container hop uses HTTP as required by Cloudflare's container API;
public requests use HTTPS, with the original host and forwarded scheme retained.

## Design

All requests use the Durable Object named `crate-pds-single`. Never change that
name, the Worker name, or its binding/migration to deploy an upgrade against the
same R2 prefix. The `durable_object` scheduling policy gives that object lifecycle
control; it does not support `max_instances`. A five-minute alarm maintains a
one-hour inactivity timeout and restarts a stopped process. Cloudflare can still
interrupt an instance. The PDS's leases protect storage during recovery.

The image is built from this checkout for linux/amd64. Wrangler resolves it to a
digest in Cloudflare's registry. Uploading a new Worker image map does **not**
replace a running container. An upgrade requires a deliberate SIGTERM, observing
exit, then starting the updated image on the same Durable Object. Do not deploy
another Worker against the same bucket/prefix as an upgrade strategy.

The Worker streams request/response bodies and WebSocket upgrades. It denies
admin, metrics, internal and debug endpoints; handle subdomains serve only
`/.well-known/atproto-did`. Public clients cannot supply operator/proxy headers.
The PDS does not yet trust a proxy CIDR: verify the container peer address before
setting `VLPDS_TRUSTED_PROXIES`, otherwise rate limits may group clients together.

## Cloudflare inputs

- Account ID; Workers Paid, Containers, and R2 enabled.
- Wrangler login (`npx wrangler login` here), or a locally stored API token with
  the permissions Wrangler reports for Workers, Containers/registry, Durable
  Objects, and the crate.social zone. Do not put credentials in tracked files.
- R2 bucket `crate-pds`, prefix `crate`; abort incomplete multipart uploads
  after one day. Bucket-scoped S3 object read/write credentials, not an R2 binding:
  vlpds needs the S3 conditional-write semantics tested by its bucket probe.
- Proxied DNS records for `pds.crate.social` and `*.crate.social`, with Worker routes
  in wrangler.jsonc. Unlike the VPS instructions these must reach the Worker.
  The existing Universal SSL certificate covers `pds.crate.social` and single-label
  handles such as `ada.crate.social`. The wildcard Worker route matches only
  `/.well-known/atproto-did`, leaving other website and app paths unchanged.
- A verified sender and Cloudflare Email Sending API token/URL. This version
  requires mail settings before startup; an SMTP adapter can replace them.
- An operator access method before opening signups: separate Access-protected
  admin routing with verified JWTs, or authenticated container exec. The public
  Worker deliberately has no admin exception. Do not temporarily expose admin.

For Free/Pro zones, the incoming request-body cap is normally 100 MB, independent
of Workers Paid. Check the actual zone plan and test large public/Spaces repo
imports and blob uploads before choosing an account to migrate. Streaming does
not bypass Cloudflare's cap. Outbound-handler limits also apply if introduced.

## Secrets and preflight

Keep an offline backup of the KEK, PLC rotation private key, and operator recovery
private key before creating or migrating accounts. Keep the recovery private key
off the server; only its did:key is configured. Generate three independent
32-byte hex values for JWT_SECRET, ADMIN_TOKEN and INTERNAL_TOKEN, and a fourth
for KEK. Generate the secp256k1 PLC key with vlpds tooling, not arbitrary text.
The Worker passes the raw PLC key using the supported
`VLPDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` variable. A wrapped PLC key cannot be
used in that variable; it requires the file-based configuration instead.

Set Worker secrets with `npx wrangler secret put NAME` (interactive input) or
`secret bulk` from a local mode-0600 file outside the repository:

```
CF_ACCOUNT_ID
S3_ACCESS_KEY
S3_SECRET_KEY
JWT_SECRET
ADMIN_TOKEN
INTERNAL_TOKEN
KEK
PLC_ROTATION_KEY_HEX
PLC_RECOVERY_DID_KEY
EMAIL_FROM_ADDRESS
EMAIL_API_URL
EMAIL_API_TOKEN
```

Use the final image and a local protected environment file to run
`vlpds-bucket-probe` against the bucket. Require its `SAFE for vlpds` result. Run
`node check-memory.mjs --docker <image>` with the shared deployment flags. The Worker budgets 3072 MiB in
standard-3 (8 GiB memory, 16 GB disk), and uses a 1024 MiB ephemeral disk cache.
No data is stored durably on container disk.

```
npm ci
npm test
npm run typecheck
npm run dry-run       # Worker bundle and configuration, no container build
npm run image-check   # Build the Linux image too (Docker required)
```

Only after the bucket probe, key backups, email and operator access are verified,
set `ENABLED` to `true` and run `npm run deploy`. Creating the deployment incurs
charges. At November 5 rates, standard-3 running 730 hours costs about $55/month
for memory and disk after included usage, plus the $5 Workers plan, active CPU,
Workers/Durable Objects, logs and network costs. No paid resources have been
created merely by adding these files.

## Acceptance before account migration

1. `describeServer`, `/.well-known/did.json`, and `/xrpc/_health` respond correctly.
2. Admin/metrics/internal/debug paths and encoded variants return 404 publicly.
3. Lease status is valid, shards owned is 1/1; restart and crash recovery preserve
   data and do not run concurrent PDS processes for the prefix.
4. Real handle subdomain TLS works; unknown handles return 404.
5. Subscribe to the firehose through the Worker and observe events, including
   after an idle period and a container restart. Verify relay reconnection.
6. Public and Spaces exports/imports round-trip through the production route,
   including representative large archives and blobs near the plan's limit.
7. Email delivery and protected operator access work. Create an invite using
   authenticated operator access. Leave signups invite-only.
8. Migrate a throwaway account first. Save its recovery key and backup; compare
   repo/blob counts and external profile/handle resolution, then request relay
   crawl. Set crawlers for restart announcements after that check.
9. Move real accounts one at a time only after the test migration passes. Each
   user's identity switch and recovery-key backup must be handled with them.

## Sources

- https://developers.cloudflare.com/containers/api/durable-object-container/
- https://developers.cloudflare.com/containers/configuration/scheduling-policy/
- https://developers.cloudflare.com/containers/platform/pricing/
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/
- ../../docs/operations/deploy.md
- ../../docs/migration.md

## Atmosphere operator login

The optional Worker gateway serves a separate `ADMIN_HOST` (the deployment uses
`admin.crate.social`) and permits only `OPERATOR_DID`
(`did:plc:4hodhjl2kposuchzvpiviwps`, resolved from `brittanyellich.com`). Configure
both variables and a route for `admin.crate.social/*`. Keep the public PDS route
and the existing Durable Object name unchanged. No container restart is needed.
The tracked template leaves this gateway unconfigured.

The official platform-neutral AT Protocol OAuth client performs PKCE, DPoP and
issuer/subject validation. Login always targets the configured DID, and the
callback checks that DID again. A one-use, ten-minute browser-bound flow creates
an opaque eight-hour session stored in Durable Object storage. Cookies are
Secure, HttpOnly, host-only and SameSite=Lax. OAuth account access tokens are not
retained. Visit the admin hostname's `/` page to sign out and revoke the session.
Removing/changing OPERATOR_DID revokes access for existing sessions immediately.

The gateway forwards only console assets and `vlpds.admin.*` calls. Every API
request requires same-origin Fetch Metadata; writes also require the exact
Origin. It removes browser cookies and supplies the existing admin token only on
the private container hop. Public admin endpoints remain blocked. The gateway
answers `getSession` in the existing UI's proxy format. **The underlying PDS audit
log still records token authentication**, not verified proxy identity: this
bridge does not enable the separate PDS admin listener. Audit actor text remains
operator-supplied. This deployment supports one operator DID.

Worker invocation logging is disabled to avoid retaining OAuth callback codes in
request URLs. Gateway errors return generic messages and do not log SDK exception
payloads. Do not enable request-URL logging on the callback route.

`npm audit` reports the current SDK's transitive Zod 3 dependency under
GHSA-mrhx-c7xc-m3w5 (unbounded validation of oversized collections); no compatible
SDK upgrade is currently offered. The gateway bounds all remote OAuth JSON to
64 KiB, 128 entries per collection, 2,048 nodes and depth 20 **before** SDK
validation. Fetches require HTTPS, reject redirects and time out after 15 seconds.
These are mitigations, not an upstream dependency fix. Revisit when the SDK ships
a compatible patched validator. Login initiation is rate-limited server-wide to
one attempt per five seconds; this can temporarily throttle legitimate logins.

Validation: `npm test`, `npm run typecheck`, `npm run dry-run`, plus the bundled
Worker in Miniflare/workerd. End-to-end acceptance requires the operator's real
OAuth consent; do not treat mocked callback tests as that acceptance.

The install hook applies one checked compatibility change to
`@atproto-labs/fetch`: construct requests with `redirect: manual`, because workerd
rejects `redirect: error` before calling the fetch adapter. The gateway adapter
then rejects every 3xx response, preserving the no-redirect requirement. The
patch fails installation if the expected upstream code changes. Run
`npm run test:runtime` after dependency upgrades. To additionally initiate a real
OAuth flow against the deployed metadata (without signing in), run that command
with `OPERATOR_LIVE_TEST=1`; it asserts a 303 without printing cookies or URLs.
