#!/bin/sh
set -eu
case "$1" in
 amd64) artifact=linux-64; sha=05099ec6f50832fcbc327490e5a971d682c97231fb01943b61726db07677e559 ;;
 arm64) artifact=linux-arm64; sha=0331597b53771170df2ab8344d9ae81d38bad4959e47152dd86592eedd9264c7 ;;
 *) exit 1 ;;
esac
cache="/opt/agent-home/.cache/kody/workerd/1.20260815.1-$artifact"
mkdir -p "$cache"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 90 "https://github.com/cloudflare/workerd/releases/download/v1.20260815.1/workerd-$artifact.gz" -o /tmp/workerd.gz
printf '%s  /tmp/workerd.gz\n' "$sha" | sha256sum -c -
gzip -dc /tmp/workerd.gz > "$cache/workerd"
chmod 555 "$cache/workerd"
rm /tmp/workerd.gz
"$cache/workerd" --version
