# Release gates — v0.3.0 identity preview

## Verified baseline

At commit 662eafd: local go vet, race tests, binary build and full CLI lifecycle succeeded. GitHub Actions runs 44700690309 and 44700681832 succeeded. This baseline does not validate subsequent commits.

## Preview gates

- [x] Initial identity implementation and local CLI lifecycle validation at baseline.
- [x] Baseline CI passed.
- [x] Document architecture, limitations and initial threat model.
- [x] Identity release-review commit d7674bb validated locally and in CI, including delegated gateway integration tests.
- [ ] Review source and remaining defects; explicitly approve preview scope.
- [ ] Confirm repository ownership/licensing and private reporting channel before external distribution.
- [x] Identity PR #2 merged into main at 24097e8.
- [ ] Verify release build artifacts, checksums, supported platforms and migration instructions before publishing a preview tag.

## Production gates — not met

- [ ] Strict method/path and MCP policy semantics, supported transports and upstream request integrity.
- [ ] TLS and upstream isolation, authenticated stdio or explicit exclusion.
- [ ] Bounded responses, rate limiting, storage lifecycle and durable recovery.
- [ ] Independent penetration test, cryptographic/protocol review and dependency review.
- [ ] Operational controls, secure key custody, audit integrity, incident response.
- [ ] Multi-node consistency if distributed operation is offered.

The preview is for isolated development with synthetic data. A green CI pipeline is not a security audit. Do not publish a production release, or advertise a certified security boundary, on this evidence.

## Gateway v0.4.0 development-preview review

- [x] Increments 1–8 locally and CI validated through 5784d51, including replay contention correction.
- [x] Increment 9 at 8bbfe0f: local module integrity, vet, ten repeated replay tests, full race suite, 21,532 local parser fuzz executions (27 new interesting inputs), binary build, CLI lifecycle and policy check passed. GitHub CI run 44711337360 succeeded.
- [x] Reconcile architecture and threat-model documentation with implemented controls; record validation evidence.
- [ ] Validate release-review documentation commit in CI; approve internal preview scope.
- [ ] Run current dependency/toolchain vulnerability scan and review remaining findings. go mod verify checks integrity, not known vulnerabilities.
- [ ] Review and merge gateway PR; confirm main CI.
- [ ] Review distribution license and private vulnerability reporting before publishing artifacts or a preview tag.

Outstanding: independent protocol/cryptography review, sustained load tests, operational key custody, replay storage recovery and pruning, complete MCP compatibility, OS isolation, tamper-evident audit, multi-node consistency and certificate lifecycle. Final admission checks narrow but do not eliminate the revocation/dispatch race. No production assurance is claimed.

## Vault v0.5.0 development-preview review

- [x] Increments 1–9 local regression and lifecycle validation, including corrected audit commit 02c6948; CI 44764585616 succeeded.
- [x] Increment 10 GitHub CI run 44775885437 succeeded at d2ad5d2, including race suite, repeated audit and brokerage regression, parser fuzz, build and synthetic CLI lifecycle.
- [ ] Independently repeat increment 10 final validation on a local developer machine (CI green; no user-local log for this commit yet).
- [x] Compare Vault branch to main: 11 ahead, 0 behind, 38 changed files at d2ad5d2. Review preview scope and explicit residual risks; not an independent code audit.
- [ ] Run a fresh govulncheck and review dependency plus supported Go toolchain vulnerabilities for the final branch. go mod verify does not scan advisories; an earlier scan at 04afc81 predates Vault.
- [ ] Independent source/protocol/cryptography review and threat-model sign-off.
- [ ] Review and explicitly approve synthetic-data preview scope; merge PR only after review and verify main CI.
- [ ] Before any distribution: resolve license and private security reporting, supported build toolchains, artifacts and recovery/migration documentation.

Unresolved production gates: persistent KEK wrap budget and aggregate storage quotas, protected KEK custody/rotation, rollback resistance and crash recovery, trusted time, dynamic provider issuance/revocation, real provider interoperability, independent security review, sustained load tests, durable tamper-evident audit, and distributed consistency. No live credentials, production approval or release tag.

## Sentinel & Ledger v0.6.0 internal development-preview review

- [x] Increment 009 developer-local repeated Sentinel/ Ledger race tests, full suite, binary build and CLI lifecycle passed at f1228a1, with clean feature branch.
- [x] GitHub CI 45037458526 succeeded at Increment 009.
- [ ] Increment 010 current commit: validate repeated Ledger, Sentinel, proxy regression, full race suite, module integrity, vet and CLI lifecycle on a developer machine and in GitHub CI.
- [ ] Independently inspect code review and explicitly approve **internal synthetic-data preview only**; a green CI run is not an independent security audit.
- [ ] Require an independently trusted, retained checkpoint Head and protected HMAC keys before restarting any real journal.
- [ ] Review crash-lock and incomplete journal/checkpoint recovery through a controlled offline process; **never** automatically delete locks or truncate a journal.
- [ ] Establish real provider-side idempotency, operator authentication, validated delivery destinations and transport receipts before live notifications.
- [ ] Resolve licensing, coordinated vulnerability reporting, release artifacts/checksums and platform support before any public tag or distribution.
- [ ] Keep auto-suspension, auto-revocation, live credentials, external alert delivery and production deployment disabled.

**Not met for production:** external rollback-resistant checkpoint anchoring, key custody, audited backups/recovery, multi-node consistency, independent security assessment, sustained load testing, integration with runtime CLI and operational alerting. No production readiness claim.
