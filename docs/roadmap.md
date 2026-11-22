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

### Gateway release review

All nine implementation increments validated locally and in CI at 8bbfe0f (CI 44711337360). Local fuzz run: 21,532 executions, 27 new interesting inputs, no failure. Release-review documentation reconciles current architecture and threat model. Dependency/toolchain vulnerability review, internal preview approval, merge and main CI remain open. No tag or distribution approval.

## Vault v0.5.0 development

Gateway merged via PR #3 at 2fcecf6. Both post-merge CI runs (44713495741, 44713489325) succeeded. Local govulncheck reported no vulnerabilities after automatic newer scanner toolchain selection; release build/scanner standardization and artifact checks remain open. No tag.

### Vault increment 1

Separate internal/vault package and documented architecture. AES-256-GCM record primitive, random data keys/identifiers/nonces, bounded KGV1 format, domain-separated authenticated record context and negative tests. No persistent storage, key wrapping, access policy or gateway integration yet. Validation pending. See [Vault architecture](VAULT_ARCHITECTURE.md).

### Vault increment 2

Increment 1 passed ten local race-test repetitions, full lifecycle and CI at 15b5236 (44714133145). Increment 2 adds explicit initialized vault identity, bounded private local encrypted record storage, exclusive immutable version publication, normal restart retrieval with caller-owned key and expected context, and tampering, substitution, permissions and concurrent writer tests. Validation pending. No live secrets; no key custody, automatic recovery, aggregate capacity bounds or gateway access.

### Vault increment 3

Increment 2 passed local repeated race tests and CI at a2689b1 (44719713905). Increment 3 adds external private KEK creation/loading, per-attempt random DEKs, domain-separated AES-GCM wrapping, immutable managed KGE1 records and restart/tamper/custody/concurrent publication tests. Validation pending. No live secrets, enforced KEK usage counter, automatic rotation, KMS or agent access yet.

### Vault increment 4

Increment 3 passed repeated local race tests, full lifecycle and CI at e344718 (44721889128). Increment 4 adds strict separate YAML Vault policy, exact identity/owner/audience/HTTPS origin/method/target/MCP tool grants, all-scopes checks, pinned secret versions and vault identity, default-deny immutable evaluation, invalid configuration and scope/operation isolation tests. Validation pending. No gateway wiring, secret reads, delegated Vault grants or injection yet.

### Vault increment 5

Increment 4 passed repeated local policy/vault tests and CI at b6a5079 (44727758123). Increment 5 adds opt-in mandatory Vault gateway authorization, independent identity/origin binding, fixed bearer injection over verified TLS, fresh admission checks, exact response token blocking and operator-only init/put CLI. Synthetic HTTPS integration and negative tests; validation pending. No production credentials, enforced KEK wrapping quota, general DLP, dynamic leases or rotation.

### Vault increment 6

Increment 5 passed five repeated local HTTPS injection race tests, full regression/lifecycle and CI at 169dba1 (44728550778). Increment 6 adds authenticated timed bearer records, mandatory expiry metadata on provisioning, maximum one-hour credential window, one-use internal leases capped at 15 seconds or remaining credential/passport life, transport deadlines and final release checks. Negative tests include legacy/future/expired record denial and lease concurrency/deadline. Validation pending. No provider-side issuance or revocation guarantees.

### Vault increment 7

Increment 6 passed repeated local lease/injection tests, regression lifecycle and CI at a3dd181 (44729786353). Increment 7 adds staged/active/retired/revoked versions, HMAC-authenticated bounded per-name lifecycle state, exclusive administrative update locks, explicit activation and revocation commands, monotonic rotation and live gateway checks before decryption/dispatch/response release. Includes restart, tamper, cross-name, concurrent activation and in-flight revocation tests. Validation pending; no rollback resistance, provider-side revocation, master key rotation or production assurance.

### Vault increment 8

Increment 7 passed repeated local lifecycle/injection tests and CI at 0c4bccf (44748823740). Increment 8 adds a provider-independent operator import interface, concrete HashiCorp KV v2 adapter (exact remote version/field, verified TLS, no redirects, bounded strict response, deletion metadata checks), staged immutable publication and synthetic HTTPS/negative tests. Validation pending. Point-in-time import only; additional providers, native dynamic issuance, source audit and live provider revocation remain open.

### Vault increment 9

Increment 8 passed repeated local provider/policy/vault/injection tests and CI at 2d4aafb (44750632476). Increment 9 adds correlated structured credential-use and operator audit, fixed metadata-only phases, checked intent writes before dispatch/mutation/release, sink failure tests and post-write live checks. Validation pending. No durable or tamper-evident Ledger, verified operator identity or proof of delivery/business success.

### Vault increment 10

Increment 9 corrected at 02c6948; repeated local audit/policy/vault/brokerage tests and full lifecycle passed, CI 44764585616 succeeded. Increment 10 latches audit sink write failures, removes redundant success log after final Vault check, tests revocation during audit writes, adds Vault binary/JSON parser fuzzing and release gates. Validation pending; internal preview only, production blockers remain open.

### Vault development-preview review status

Increment 010 CI at d2ad5d2 succeeded (44775885437), including repeated audit/brokerage tests, race suite, parser fuzzing, build and CLI lifecycle. The branch is 11 commits ahead of main with no divergence at that snapshot. Documentation and PR review are still required. No live credentials, production release or distribution tag approved. Run current govulncheck before merge review; Go 1.23.4 is the declared module toolchain, and the earlier scan predates Vault.

## Sentinel & Ledger v0.6.0 development

Vault v0.5.0 internal development preview merged into main at 70e2fad; post-merge CI 45010568020 passed. Increment 001 starts a separate authenticated canonical event-chain primitive with independently supplied HMAC key and stream ID, bounded verification, serialization and failure-latching tests. Validation pending. No persistence, external checkpoint, runtime integration, real detection or production guarantees; see [architecture](SENTINEL_LEDGER_ARCHITECTURE.md).

### Sentinel & Ledger increment 002

Increment 001 local repeated race regression and GitHub CI 45011269258 passed. Increment 002 introduces a private synced single-host journal with exclusive lock, expected-head reopening, filesystem identity/size validation, and explicit fail-closed crash semantics. Local and CI validation pending; no external checkpoint or runtime integration.

### Sentinel & Ledger increment 003

Increment 002 passed ten repeated race tests, complete local regressions, and CI at 0d2bd91 (45012179648). Increment 003 adds a separate local HMAC-authenticated checkpoint with a distinct key, durable atomic snapshot publication, combined append and verified restart, explicit independent expected-head requirement, and fail-closed interrupted-commit behavior. No external anchoring, key management, safe crash recovery, distributed writes or runtime audit integration; validation pending.

### Sentinel & Ledger increment 004

Increment 003 passed ten repeated local race tests and full regression, plus CI 45019143269. Increment 004 adds an explicitly constructed Vault audit-to-Ledger writer adapter, checked canonical event parsing, journal-plus-checkpoint acknowledgement, fail-closed writer latching and a real Vault HTTPS handler integration regression. No CLI opt-in, external checkpoint trust or operator-managed key custody yet; validation pending.

### Sentinel & Ledger increment 005

Increment 004 passed local repeated Ledger, Vault integration and full race tests, plus GitHub CI 45023064147. Increment 005 adds a standalone bounded advisory detector for unique-attempt denial, exchange-failure and withheld-response bursts, with per-identity sliding windows, explicit capacity errors, deterministic time/clock tests and concurrency tests. Replay, rate-limit and full behavioural monitoring remain unimplemented. CI/local validation pending.

### Sentinel & Ledger increment 006

Increment 005 passed repeated local Sentinel race tests, Ledger suite, full regression, lifecycle and GitHub CI 45026876140. Increment 006 adds bounded operator-review incident cases with write-before-state-transition recording into the checkpointed Ledger, strict revision/state validation, explicit fail-closed incident storage errors, and synthetic end-to-end tests. No external delivery, authenticated operator RBAC, restart reconstruction or automatic mitigation; validation pending.

### Sentinel & Ledger increment 007

Increment 006 passed local ten-repeat Sentinel races, five-repeat Ledger race tests, the full suite and CI 45027981372. Increment 007 implements bounded verified journal history and strict replay of incident transitions into the in-memory incident manager, with no automated recovery, external trust or runtime gateway wiring. Validation pending.

### Sentinel & Ledger increment 008

Increment 007 passed ten-repeat local Sentinel race tests, five-repeat Ledger race tests, full regression and CI 45030737153. Increment 008 introduces manual advisory delivery with a stable idempotency ID, bounded retries/timeouts, checked pre-send intent and outcome records in Ledger, sanitized notices and fail-closed storage errors. Transport is operator-supplied; no real provider adapter, restart delivery recovery or runtime Gateway configuration. Validation pending.

### Sentinel & Ledger increment 009

Increment 008 passed local repeated Sentinel/ Ledger race tests, full integration and CLI lifecycle, with GitHub CI 45033403402. Increment 009 adds full bounded, checkpoint-verified ordered incident/delivery history replay, reconstruction of accepted/failed/queued/uncertain delivery states, strict transition validation, and a safeguard rejecting fresh dispatchers that could forget previous accepted/uncertain sends. No operator/provider reconciliation API, external anchor, real delivery transport or runtime CLI activation; CI/local validation pending.

### Sentinel & Ledger increment 010

Increment 009 passed user-local ten-repeat Sentinel race tests, five-repeat Ledger race tests, full suite and lifecycle, plus CI 45037458526. Increment 010 focuses on adversarial replay ID uniqueness, duplicate terminal outcomes, authenticated journal tampering, residual-risk disclosure and internal preview gates. No independent assurance, distribution license change, main merge, production use or automatic enforcement. Validation pending.
