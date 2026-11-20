#!/usr/bin/env bash
# Exercise a freshly compiled binary without touching existing keys or state.
set -euo pipefail

if [[ $# -ne 1 || "$1" != /* || ! -x "$1" ]]; then
  echo "Usage: bash scripts/test-passport-lifecycle.sh /absolute/path/to/kgaga" >&2
  exit 2
fi
kgaga="$1"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
cd "$work"
umask 077
"$kgaga" init

expect_failure() {
  local expected="$1"
  shift
  if "$@" > result.out 2> result.err; then
    echo "Expected command to fail: $*" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" result.err; then
    echo "Unexpected failure reason: $*" >&2
    cat result.err >&2
    exit 1
  fi
  if [[ -s result.out ]]; then
    echo "Rejected verification returned unexpected stdout" >&2
    exit 1
  fi
}

expect_failure "open agent registry failed" "$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api
"$kgaga" agents-init
expect_failure "mint rejected: agent authorization denied" "$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api
"$kgaga" agent-register --agent smoke-agent --owner ops@example.com --scopes db:read --audiences support-api
"$kgaga" agent-inspect --agent smoke-agent | python3 -c 'import json,sys; a=json.load(sys.stdin); assert a["agent_id"]=="smoke-agent" and not a["suspended"]'
expect_failure "mint rejected: agent authorization denied" "$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:write --audience support-api
"$kgaga" keys-init
old_kid=$("$kgaga" key-trust --public kgaga.pub)
token=$("$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api --ttl 15m)

# Missing state must not silently become an empty revocation store.
expect_failure "open revocation store failed" "$kgaga" verify --audience support-api <<< "$token"
"$kgaga" revocations-init
claims=$("$kgaga" verify --audience support-api <<< "$token")
jti=$(python3 -c 'import json,sys; c=json.load(sys.stdin); assert c["agent_id"]=="smoke-agent" and c["aud"]==["support-api"]; print(c["jti"])' <<< "$claims")
expect_failure "passport verification failed" "$kgaga" verify --audience payments-api <<< "$token"
"$kgaga" revoke --id "$jti"
expect_failure "passport rejected: passport revoked" "$kgaga" verify --audience support-api <<< "$token"
fresh=$("$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api --ttl 15m)
"$kgaga" verify --audience support-api <<< "$fresh" > /dev/null
"$kgaga" key-generate --out replacement
new_kid=$("$kgaga" key-trust --public replacement/kgaga.pub)
rotated=$("$kgaga" mint --signing-key replacement/kgaga.key --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api)
"$kgaga" verify --audience support-api <<< "$rotated" >/dev/null
"$kgaga" keys-list | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["keys"])==2'
"$kgaga" key-retire --kid "$old_kid"
expect_failure "passport verification failed" "$kgaga" verify --audience support-api <<< "$fresh"
expect_failure "mint rejected: signing key or passport rejected" "$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api
"$kgaga" keys-list | python3 -c 'import json,sys; keys=json.load(sys.stdin)["keys"]; assert len(keys)==1 and keys[0]["kid"]==sys.argv[1]' "$new_kid"
"$kgaga" verify --audience support-api <<< "$rotated" >/dev/null
fresh="$rotated"
"$kgaga" agent-suspend --agent smoke-agent
expect_failure "passport rejected: agent authorization denied: suspended agent" "$kgaga" verify --audience support-api <<< "$fresh"
expect_failure "mint rejected: agent authorization denied: suspended agent" "$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api
echo "PASS: registration, scope limits, issuance, audience binding, revocation, key rotation and agent suspension"
