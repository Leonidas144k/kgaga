# Kgaga identity architecture

Status: development preview, reviewed against 662eafd.

## Trust boundaries

- Trusted local operator enrolls identities, approves scopes and audiences, manages key trust and signs credentials. Access to issuer private keys or state is privileged.
- Agent holds its own Ed25519 private key. Only its public key is registered. A five-minute one-time challenge proves possession at new CLI enrollment, not independent workload integrity.
- Gateway reads public trust, registry, revocation and replay stores; it does not require the issuer private key for HTTP verification.
- Protected upstream must not be directly accessible by agents. It must trust identity headers only over an authenticated gateway connection.
- Authenticated lockstep stdio uses the same identity and local replay stores, a distinct audience, synthetic STDIO request-proof binding, one pinned passport per child and matching response IDs. The operator must isolate the child at OS level.

## Components

| Package | Responsibility |
| --- | --- |
| passport | Ed25519 JWTs, thumbprints, holder confirmation, request proofs, enrollment and delegation signatures |
| keyring | Trusted public keys, retirement, live JWKS |
| registry | Immutable approved agent identities, challenge consumption, permanent suspension |
| revocation | Persistent credential and separate proof-nonce markers |
| delegation | One-hop issuer-mediated delegated credentials and live parent validation |
| proxy | HTTP admission, policy, limited MCP inspection, forwarding and audit |
| policy | YAML v2 longest segment-prefix rules, explicit methods, tool scope checks and regex redaction |
| mcp | Initial JSON-RPC envelope inspection |

## Request lifecycle

1. Select a trusted issuer key by kid, verify signature, type, issuer, exact audience and time claims.
2. Check credential revocation and registered agent ownership, scopes, audience, suspension and holder thumbprint.
3. For delegated credentials verify the original parent's current trust, revocation, registry and grant restrictions.
4. Bound and read request body; verify holder signature over the passport digest, exact target, method, selected headers, body digest, time and nonce.
5. Atomically consume the proof nonce in the dedicated local replay store.
6. Evaluate HTTP policy or exact POST /mcp policy; redact recognised patterns if enabled; populate verified identity headers and strip the passport and proof before forwarding.

JWKS is a public verification-key view, not a complete authorization decision. The verify CLI inspects credentials without proving a current request. The gateway authenticates the original request before rewriting/redaction; this is not end-to-end message integrity.

## State and operational constraints

Use separate protected directories for registry, revocation, trust and replay. Filesystem markers are single-host and retained indefinitely; hard links are required for some records. Normal process restarts preserve records, but crash/power-loss guarantees, distributed synchronization, state rollback protection and pruning are not established. Issuer selection is manual; key retirement and agent suspension are permanent through the CLI. Delegation is one-hop, same owner and audience, scope-restricted, expires no later than its parent. Grants are reusable until expiry.

## Next architecture

A hardened HTTP/MCP boundary precedes vault, audit ledger and enterprise control plane. Independent workload attestation, standard protocol interoperability, secure remote issuance, secret management and multi-node consistency are not included in this preview.
