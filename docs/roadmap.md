# Kgaga engineering roadmap

Kgaga is AFROSOFT's agent identity and security project. Preserve the Go core and ship in reviewed increments.

## v0.2.0 — foundation

- [x] Rename CLI, module, policy configuration and release artifact names.
- [ ] Rename repository through GitHub settings, add approved branding assets, validate trademark.
- [ ] Build, vet, race-test and review migration from v0.1; do not publish until green.
- [ ] Bound HTTP request size and read errors; configure server timeouts, align JWKS with the actual verification key, validate upstream targets.
- [ ] Test malformed MCP calls, mismatched headers, denied scopes, invalid/expired signatures and default deny.
- [ ] Threat model: malicious agents, untrusted MCP servers, token theft and replay, policy bypass, leaked secrets, compromised key storage and operator error. Treat stdio as experimental until authenticated and fail-closed.

## v0.3.0 — identity

Audience binding, agent registration, key IDs and rotation, credential revocation, scoped delegation and proof-of-possession design. Explicitly plan issuer/header migration; do not create an unauthenticated compatibility path.

## v0.4.0 — gateway

MCP transport compliance, strict policy matching, authenticated stdio, response inspection and bounded streaming, integration tests, protected audit trail.

## Later

Managed control plane, SDKs, enterprise pilots, independent security assessment, commercial launch. No production-ready claim before release gates are met.
