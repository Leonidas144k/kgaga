# Kgaga engineering roadmap

Kgaga is AFROSOFT's agent identity and security project. Preserve the Go core and ship in reviewed increments.

## v0.2.0 — foundation

- [x] Rename CLI, module, policy configuration and release artifact names.
- [ ] Rename repository through GitHub settings, add approved branding assets, validate trademark.
- [ ] Build, vet, race-test and review migration from v0.1; do not publish until green.
- [x] Implement initial HTTP request limit (1 MiB), read errors, header/read/idle timeouts, matching JWKS key and upstream URL checks; verify in CI.
- [x] Add regression tests for malformed MCP calls, mismatched headers, denied scopes, invalid/expired signatures and default deny; execution pending CI.
- [ ] Threat model: malicious agents, untrusted MCP servers, token theft and replay, policy bypass, leaked secrets, compromised key storage and operator error. Treat stdio as experimental until authenticated and fail-closed.

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

Local immutable agent registry, registration, inspection, permanent suspension, mandatory registry authorization at CLI mint/verify and v2 gateway, and tests. Operator filesystem permissions remain the trust boundary; no resume, record editing, distributed state or independent attestation. Pending validation.
