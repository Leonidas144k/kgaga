# Release gates — v0.3.0 identity preview

## Verified baseline

At commit 662eafd: local go vet, race tests, binary build and full CLI lifecycle succeeded. GitHub Actions runs 44700690309 and 44700681832 succeeded. This baseline does not validate subsequent commits.

## Preview gates

- [x] Initial identity implementation and local CLI lifecycle validation at baseline.
- [x] Baseline CI passed.
- [x] Document architecture, limitations and initial threat model.
- [ ] Validate new release-review commit, including delegated HTTP gateway integration tests.
- [ ] Review source and remaining defects; explicitly approve preview scope.
- [ ] Confirm repository ownership/licensing and private reporting channel before external distribution.
- [ ] Merge reviewed PR into main after green CI.
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
- [ ] Increment 9 local and CI validation, including adversarial regression tests and short fuzzing.
- [ ] Review final diff, dependency advisories, documentation and residual risks; approve internal preview scope.
- [ ] Review and merge gateway PR; confirm main CI.
- [ ] Review distribution license and private vulnerability reporting before publishing artifacts or a preview tag.

Outstanding: independent protocol/cryptography review, sustained load tests, operational key custody, replay storage recovery and pruning, complete MCP compatibility, OS isolation, tamper-evident audit, multi-node consistency and certificate lifecycle. Final admission checks narrow but do not eliminate the revocation/dispatch race. No production assurance is claimed.
