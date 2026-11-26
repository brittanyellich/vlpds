#!/bin/sh
set -eu

: "${EXP711_WORKERD:?Set EXP711_WORKERD to the local workerd executable}"
: "${EXP711_OAUTH_PROVIDER:?Set EXP711_OAUTH_PROVIDER to the local OAuth provider bundle}"
case "$EXP711_WORKERD" in /*) ;; *) echo "EXP711_WORKERD must be an absolute path" >&2; exit 2 ;; esac
case "$EXP711_OAUTH_PROVIDER" in /*) ;; *) echo "EXP711_OAUTH_PROVIDER must be an absolute path" >&2; exit 2 ;; esac
test -f "$EXP711_WORKERD" && test -x "$EXP711_WORKERD" || { echo "workerd is not executable" >&2; exit 2; }
test -f "$EXP711_OAUTH_PROVIDER" && test -r "$EXP711_OAUTH_PROVIDER" || { echo "Provider bundle is not readable" >&2; exit 2; }

cd "$(dirname "$0")/../.."
node --test tools/spaces-mcp-auth-fixture/preview-package.test.mjs
log="$(mktemp "${TMPDIR:-/tmp}/exp711-preview-check.XXXXXX")"
trap 'rm -f "$log"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! cargo test --offline --locked --test all -- ident_link_binding spaces_mcp_chat --nocapture >"$log" 2>&1; then
    grep -E '^(error:|test .*FAILED|test result:)' "$log" >&2 || true
    echo "Preview validation failed. Re-run the focused cargo command for local diagnostics." >&2
    exit 1
fi

# A passing Rust suite alone is insufficient when Worker checks were skipped.
for marker in \
    'Passed browser sign-in and one-time OAuth consent over the disposable PDS route' \
    'Passed OAuth consent bound to authenticated disposable PDS owner sessions' \
    'Passed OAuth-authorized Spaces writes/history, two-owner binding, audience isolation, and grant revocation' \
    'Passed fresh ident.link verification at MCP dispatch on already-issued tokens'
do
    grep -Fxq "$marker" "$log" || { echo "Missing preview evidence: $marker" >&2; exit 1; }
    printf '%s\n' "$marker"
done
grep '^test result: ' "$log"
