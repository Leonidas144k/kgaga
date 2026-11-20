# Changelog

## Unreleased — v0.4.0 gateway development

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
