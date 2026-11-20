# Kgaga engineering roadmap

Kgaga is AFROSOFT's agent identity and security project. Preserve the Go core and ship in reviewed increments.

## v0.2.0 — foundation

- [x] Rename CLI, module, policy configuration and release artifact names.
- [ ] Rename repository through GitHub settings, add approved branding assets, validate trademark.
- [ ] Build, vet, race-test and review migration from v0.1; do not publish until green.
- [x] Implement initial HTTP request limit (1 MiB), read errors, header/read/idle timeouts, matching JWKS key and upstream URL checks; verify in CI.
- [x] Add regression tests for malformed MCP calls, mismatched headers, denied scopes, invalid/expired signatures and default deny; execution pending CI.
- [x] Initial threat model documented; mitigations and independent review remain open. Treat stdio as experimental until authenticated and fail-closed.

## v0.3.0 — identity

Audience binding, agent registration, key IDs and rotation, credential revocation, scoped delegation and proof-of-possession design. Explicitly plan issuer/header migration; do not create an unauthenticated compatibility path.

## v0.4.0 — gateway

MCP transport compliance, strict policy matching, authenticated stdio, response inspection and bounded streaming, integration tests, protected audit trail.

## Later

Managed control plane, SDKs, enterprise pilots, independent security assessment, commercial launch. No production-ready claim before release gates are met.

The CLI binds to loopback by default. Explicit non-loopback deployment needs TLS and network access controls. Full streaming, response limits, replay resistance, revocation and authenticated stdio remain open.

### Identity increment 1

Implemented strict v2 issuance and verification, key thumbprints, unique credential IDs, mandatory time claims, maximum TTL, exact single audience, CLI verification and audience-bound HTTP gateway. Legacy tokens require reissuance; no CLI fallback. Increment 1 CI and local tests passed. Key rotation, agent registry and proof of possession remain outstanding.

### Identity increment 2

Local persistent passport revocation: explicit store initialization, exclusive per-ID markers, CLI revoke, check on CLI verify and audience-bound gateway, fail closed on store errors, and regression tests. No database or new dependencies. Distributed state, pruning, backups, power-loss durability, trusted operator access and replay resistance require further design. Increment 2 CI and local smoke test passed at 81f16e3.

### Identity increment 3

Local immutable agent registry, registration, inspection, permanent suspension, mandatory registry authorization at CLI mint/verify and v2 gateway, and tests. Operator filesystem permissions remain the trust boundary; no resume, record editing, distributed state or independent attestation. Increment 3 GitHub CI passed at 4e8f0bb; local CLI confirmed.

### Identity increment 4

Explicit trusted signing keyring, generation into a new directory, public-key trust, manual issuer selection and permanent retirement, live JWKS, mandatory keyring checks and regression tests. Single-host operator-controlled storage; no automatic rotation, distributed trust synchronization or HSM support. Increment 4 CI and local smoke passed at 4fa2abf.

### Identity increment 5

Holder confirmation in passports, immutable registered agent public key, strict HTTP request proof verification, and atomic local replay marker consumption. Credential inspection is not live proof. Legacy unbound passports are denied by CLI/gateway. Custom development protocol, no standards compliance claim. Distributed replay state, full request integrity, durable pruning and independent review outstanding. Increment 5 local and GitHub CI passed at de23553.

### Identity increment 6

Operator-issued single-use enrolment challenges, holder signatures over full proposed registration, expiry, replay rejection, concurrency tests and CLI lifecycle coverage. This is possession at enrolment, not independent workload or hardware attestation. Existing holder-bound identities remain compatible. Enrollment CI and local lifecycle passed at 662eafd; independent workload attestation remains pending.

### Identity increment 7

One-hop issuer-mediated delegation with explicit parent scope, signed parent grant, exact child holder binding, same owner/audience, permission subset, bounded expiry and parent lifecycle checks. Separate JWT type prevents old verifiers accepting the new format. Reusable grants are not independently revocable; parent revocation disables descendants. No nested delegation. Local lifecycle, race tests, vet, build and both GitHub CI runs passed at 662eafd. Independent workload attestation remains unimplemented.

## Release review

See [release checklist](RELEASE_CHECKLIST.md), [threat model](THREAT_MODEL.md) and [architecture](ARCHITECTURE.md). Do not confuse completion of initial identity implementation with readiness to operate a security boundary. Prioritize safe request forwarding and policy semantics before an external pilot.

### Gateway increment 1

HTTP policy v2: explicit method allowlists, segment-boundary longest-prefix authorization, no broader fallback, ambiguous winning rules deny, literal canonical paths, root-only upstream origin, exact POST /mcp classification, common routing override rejection and regression tests. Version 1 policy files must be migrated intentionally. Full YAML validation, strict MCP parsing, complete forwarding integrity and independent security review remain pending. Validation pending.

### Gateway increment 2

Strict bounded single-document YAML schema and semantic validation, programmatic policy snapshots, explicit empty MCP tool deny semantics, policy-check CLI and smoke coverage. Increment 1 validated locally and in CI at 7f66a2f. Increment 2 tests pending; parser hardening and transport security remain outstanding.

### Gateway increment 3

Strict bounded JSON-RPC HTTP inspector, full-tree duplicate key detection, exact envelope keys, explicit supported methods, request IDs, tool tuple validation, transport/header checks, fixed JSON errors, and block rather than rewrite detected MCP secrets. Signed gateway regression tests added. Increment 2 passed local and CI at 8cfcd71. Increment 3 validation pending. No complete MCP protocol conformance, session lifecycle, response validation or authenticated stdio guarantee.

### Gateway increment 4

Replace unsigned stdio wrapper with authenticated single-passport signed frames, per-message identity and replay checks, strict shared MCP parser, lockstep response-ID validation, bounded child pipe I/O, and CLI smoke coverage. No transparent native client support, OS sandbox, full-duplex session, or production assurance. Increment 3 passed local and CI at 3c0955e; increment 4 validation pending.

### Gateway increment 5

Bounded HTTP exchange with explicit forwarding header allowlists, no redirects or streaming, restricted UTF-8 JSON/text bodies, request/response secret-pattern checks including decoded JSON and query values, strict MCP response IDs, lifecycle recheck before response release, and signed gateway regression tests. Increment 4 passed local/CI at 6dced6b. Increment 5 validation pending. No comprehensive DLP or aggregate concurrency/security guarantee.

### Gateway increment 6

Mandatory local token-bucket agent rate limiting with optional strict YAML settings, stable ID keys, HTTP 429/Retry-After and bounded tracking capacity (503), per-session stdio rate limits, no depleted-bucket eviction, and deterministic concurrency/policy/gateway tests. Increment 5 passed local and CI at e8b8f78. Increment 6 validation pending. Limits are in-memory per handler/session, not distributed, durable or aggregate parent quotas.

### Gateway increment 7

Fixed aggregate HTTP admission and concurrency ceilings, capped accepted TCP and upstream connections, write deadline, persistent replay reservation ceiling with legacy migration and cross-process lock, and regression tests. Increment 6 passed local and CI at 730a8e6. Increment 7 validation pending. No automated pruning, complete disk accounting, distributed quotas, or production DoS guarantee.

#### Increment 7 contention correction

CI passed at 186079b but local race tests reproduced premature 100 ms replay quota lock failures under filesystem contention. Use one filesystem lock protocol with a three-second acquisition budget and typed busy error; remove the unbounded per-Store mutex queue. Test deliberate slow-writer contention, fail-closed timeout, duplicate nonce exclusion, persistent quota count and retry only the pre-reservation busy outcome in concurrent tests. Local/CI revalidation required.

### Gateway increment 8

Verified TLS 1.2+ upstream connections by default, optional private trust roots and client certificates, literal-loopback-only explicit HTTP opt-in, non-loopback listener TLS requirement, and TLS/mTLS negative tests. Increment 7 replay fix passed CI and repeated local race tests at d059a2f. Increment 8 validation pending. Upstream must enforce client certificate authorization and network isolation; no automatic rotation or CRL/OCSP enforcement.

### Gateway increment 9

Closed v2 credential wire schema and canonical proof signature encoding; final live authorization/proof freshness rechecks before dispatch in both transports; concurrent replay, in-flight revocation and signed ambiguity regression tests; short envelope fuzzing and repeated replay tests in CI. Increment 8 passed local and CI at 5784d51. Increment 9 validation pending; external security assurance and operational release gates remain open.
