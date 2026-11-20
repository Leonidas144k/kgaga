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
token=$("$kgaga" mint --agent smoke-agent --owner ops@example.com --scopes db:read --audience support-api --ttl 15m)

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
echo "PASS: issuance, correct audience, wrong audience rejection, persistent revocation and fresh passport verification"
