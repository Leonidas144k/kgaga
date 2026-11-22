# Changelog

## Unreleased — v0.6.0 Sentinel & Ledger development

- Add explicit manual advisory delivery interface with audited intent/outcomes, retry limits, idempotency metadata, and sanitized operator notices. Transport plugin and restart replay pending.

- Restore advisory incident state from bounded fully verified checkpointed Ledger history, rejecting orphaned, conflicting or malformed transitions; no automatic crash recovery.

- Add advisory Sentinel incident records with bounded open/acknowledged/resolved workflow, explicit operator review and checkpointed Ledger evidence; programmatic opt-in only.

- Add bounded in-memory advisory Sentinel detector for credential denials, exchange failures and withheld responses, with unique-attempt correlation and conservative alert suppression; no enforcement or gateway runtime wiring.

- Add explicit Vault audit-to-Ledger writer adapter and broker injection API with fail-closed verified persistence. Programmatic opt-in only; CLI remains unchanged.

- Add separate authenticated checkpoint snapshots and combined journal/checkpoint append and restart verification with independent expected heads; no external trust anchor or automated crash recovery.

- Add single-host synced Ledger journal, checked restart continuity, private-file and lock checks, with failure/recovery tests. No independent checkpoint storage or runtime audit integration.

- Add isolated canonical HMAC-linked JSONL event chain and bounded verifier; no runtime integration or durable audit support yet.


## Unreleased — v0.5.0 vault development

- Document completed Vault implementation and CLI preview semantics, successful Increment 010 CI evidence and explicit remaining release gates. No production release authorization.

- Latch audit sink write failures, regression-test revocation during dispatch/release intent, fuzz Vault formats in CI, and document development-preview release gates.

- Add structured correlated Vault usage and operator audit events with checked intent writes and fail-closed dispatch/release on writer errors. Durable and tamper-evident Ledger remains future work.

- Add operator-only version-pinned HashiCorp KV v2 HTTPS imports via a provider interface. Imported credentials remain staged and require local activation; no live fetch or automatic provider revocation propagation.

- Add staged/active credential lifecycle with explicit activation, monotonic rotation, revocation, authenticated persistent state and live gateway checks. Existing records require activation; pinned policies do not automatically advance.

- Require authenticated timed bearer records in Vault mode; enforce one-hour maximum credential validity and per-request single-use leases capped at 15 seconds, with deadline-bound exchanges. Existing untimed tokens require explicit new version provisioning.

- Add opt-in HTTPS Vault gateway mode with mandatory exact grants, fixed bearer injection, exact-token response inspection and local operator stdin provisioning. No general DLP or production assurance.

- Add strict deny-by-default Vault access policy evaluator with exact operation and agent grants, literal required scopes, pinned secret metadata and no delegated access. Gateway enforcement follows separately.

- Add managed envelope encryption with separate local operator KEK custody, fresh DEKs, authenticated wrapping and single-file immutable publication. No automatic key rotation or gateway access.

- Add private local immutable encrypted record storage with explicit identity, bounded reads, exclusive publication and restart/concurrency regression tests. Caller-managed data keys only.

- Add isolated AES-256-GCM record primitives with authenticated record metadata, bounded versioned ciphertext format, cryptographic key/nonce generation and tamper tests. No storage or agent/gateway secret API yet.

## Unreleased — v0.4.0 gateway development

- Adversarial regression coverage: reject ambiguous signed v2 envelopes, recheck live credentials and proof freshness before dispatch, repeat replay tests and fuzz the envelope parser in CI.

- Require verified HTTPS upstream by default; private CA and client TLS credentials supported. Explicit literal-loopback HTTP opt-in; require TLS for non-loopback gateway binds.

- Correct replay quota lock contention: bounded three-second acquisition, typed busy error and strengthened contention/duplicate tests; security ceilings and exclusive nonce writes unchanged.

- Bound aggregate HTTP admission, active handlers, TCP/upstream connections and write time. Cap persistent replay reservations without pruning; reject shared replay/revocation directories. Offline recovery required after a crash lock.

- Mandatory per-agent token buckets, optional validated rate_limit settings, HTTP 429/Retry-After, bounded tracking and stdio session admission. Counters are local and reset on restart.

- Bounded buffered HTTP request/response inspection, restricted forwarding headers and content types, matched MCP response IDs, and bidirectional block-on-secret policy. Existing transparent proxy behavior is intentionally restricted.

- Replace unsigned stdio wrapper with signed frames, live identity/scope checks, lockstep response validation and a frame-signing CLI. Native clients need an adapter; OS isolation remains required.

- HTTP policy version 2 requires explicit allowed methods; most-specific segment prefix wins, no broader fallback.
- Reject ambiguous/nonliteral paths, common routing overrides, upstream base paths/queries and header-selected MCP routing.
- Existing v1 policies require intentional migration.
- Strict YAML schema and semantic validation; standalone policy-check; immutable gateway policy snapshot and explicit empty MCP tool deny behavior.
- Restricted HTTP MCP parser: reject duplicate/ambiguous JSON, unsupported methods, malformed requests and detected secret patterns; add signed gateway tests. Full protocol/session/response validation remains pending.


## Unreleased — v0.3.0 identity preview

### Added
- Audience-bound Ed25519 Agent Passports with mandatory validity claims and unique IDs.
- Local credential revocation, agent registry and permanent suspension.
- Multi-key trust store, manual rotation, permanent key retirement and live JWKS.
- Holder-bound passports, request proofs and single-host replay markers.
- Challenge-based CLI enrollment and one-hop issuer-mediated delegation with live parent checks.
- CLI lifecycle regression tests and initial security documentation.

### Changed
- Explicit initialization of trust, registry, revocation and replay state.
- Legacy unbound credentials are rejected in the current CLI and HTTP gateway.
- Existing identities without holder keys require newly registered IDs. Existing holder-bound identities are not retroactively challenge-attested.
- Delegated credentials carry a distinct JWT type; older builds reject it.

### Limitations
Development preview only. Local state, manual rotation, custom proof protocols, reusable grants, experimental unauthenticated stdio, incomplete HTTP/MCP policy and response hardening. No production-readiness or independent assurance claim.

## Foundation — v0.2.0 baseline

Kgaga rebranding and initial gateway hardening merged into main at 66d406e. Version tag publication is not asserted.
