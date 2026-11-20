# Kgaga identity and gateway architecture

Status: development preview. Identity merged at 24097e8; gateway implementation baseline 8bbfe0f passed local and CI validation. Not an independent security assessment.

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
| proxy | Aggregate admission, agent quotas, verified upstream TLS, restricted buffered exchanges, authenticated lockstep stdio and decision logging |
| policy | Strict YAML v2, longest segment-prefix rules, explicit methods, tool scope checks, token buckets and secret-pattern inspection |
| mcp | Restricted JSON-RPC request and matching response validation |

## Request lifecycle

1. Bound connection and handler admission, apply aggregate quota and validate literal request route.
2. Select a trusted issuer key by kid; require exact credential schema, valid signature, type, issuer, audience and time claims.
3. Check revocation, registered ownership, scopes, audience, suspension and holder thumbprint; revalidate any delegated credential's parent and grant.
4. Bound and read request body; verify holder signature over passport digest, exact target, method, selected headers, body digest, time and nonce.
5. Charge the registered agent's rate bucket, then reserve replay capacity and exclusively consume the nonce in the dedicated store.
6. Evaluate HTTP or restricted POST /mcp policy; inspect payload and selected metadata, blocking recognized secret patterns when enabled. Recheck current credentials and proof freshness before dispatch.
7. Forward the original admitted body with selected headers and verified identity over verified HTTPS (explicit loopback HTTP is development-only). Never forward the passport or proof. Buffer and inspect bounded upstream response; for MCP validate matching ID or supported notification response.
8. Recheck live credentials before releasing response bytes. Already dispatched effects cannot be undone.

JWKS is a public verification-key view, not a complete authorization decision. The verify CLI inspects credentials without proving a current request. The gateway signs/verifies only selected inbound fields and forwards an allowlisted set of headers. It no longer rewrites recognized secrets when inspection is enabled. This is not end-to-end message integrity.

## State and operational constraints

Use separate protected directories for registry, revocation, trust and replay. Filesystem markers are single-host and retained indefinitely; hard links are required for some records. Replay reservations have a fixed one-million ceiling and a bounded lock contention budget. A stale crash lock blocks further admissions until controlled offline recovery. Local rate buckets reset on restart. Normal process restarts preserve records, but crash/power-loss guarantees, distributed synchronization, state rollback protection and pruning are not established. Issuer selection is manual; key retirement and agent suspension are permanent through the CLI. Delegation is one-hop, same owner and audience, scope-restricted, expires no later than its parent. Grants are reusable until expiry.

## Next architecture

A hardened HTTP/MCP boundary precedes vault, audit ledger and enterprise control plane. Independent workload attestation, standard protocol interoperability, secure remote issuance, secret management and multi-node consistency are not included in this preview.

## Vault development foundation

Gateway merged at 2fcecf6; post-merge CI passed. The separate internal/vault cryptographic foundation is under development on the Vault branch; see [Vault architecture](VAULT_ARCHITECTURE.md). It does not yet change the request lifecycle or provide secret storage or injection.

Vault increment 002 adds the isolated operator-only immutable encrypted record store. Caller-owned keys remain outside storage; no agent or gateway integration. See VAULT_ARCHITECTURE.md for trust and recovery constraints.

Vault increment 003 introduces managed envelope encryption with an external operator-held KEK file, per-attempt random DEKs and immutable KGE1 records. The KEK file is plaintext under separate local custody, not KMS/HSM-backed. No agent-facing secret API or changes to gateway forwarding.
