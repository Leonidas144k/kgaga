# Threat model — identity and gateway development preview

Scope: internal implementation review through gateway baseline 8bbfe0f, not an independent penetration test or certification. Threats include malicious agents, compromised holder keys, network attackers, hostile upstream/MCP servers, privileged operator error and state loss.

## Assets and assumptions

Protect issuer and holder keys, enrolled identities and permissions, credential lifetimes, revocation/retirement/suspension records, replay state, upstream data and audit events. The operator, OS, clock, local filesystem and configured upstream are trusted in current tests. Keep services isolated, use synthetic data and do not expose listeners publicly. A compromised privileged operator or issuer is outside the current protection model.

## Threat register

| Threat | Current control | Residual risk / required work |
| --- | --- | --- |
| Forged, expired or wrong-audience passport | Ed25519, exact wire schema, strict claims, trusted kid, exact audience | Independent JWT/parser review; issuer compromise |
| Stolen passport | Registered holder thumbprint and signed HTTP request | Full captured proof can race original; compromised key impersonates holder |
| Replayed proof | Freshness checks, exclusive nonce marker and persistent reservation ceiling | Storage saturation, stale lock recovery, clock rollback, multiple hosts, state rollback |
| Unauthorized registration | Operator approval and new CLI challenge proof | No independent identity/workload attestation; older registrations not retroactively checked |
| Excess delegation | Same owner and audience, subset, expiry bound, parent checks | Grant reuse, no independent grant revocation; non-atomic dispatch/revocation |
| Compromised issuer | Explicit trust and permanent retirement | Manual rotation; state trust and in-flight requests; no HSM |
| State loss or replacement | Running process checks directory identity; deny on errors | Restart cannot establish trusted history; backups and rollback protection required |
| Policy boundary ambiguity | Exact methods, canonical paths, longest segment prefix, strict config, scope and tool checks | Upstream routing semantics and authorization must match; independent bypass review |
| Protocol confusion | Restricted JSON-RPC parser, duplicate rejection, exact route and response IDs | Full MCP schemas, sessions, streaming and compatibility remain incomplete |
| Request transformation | Signed selected inbound fields and explicit forwarding allowlist | Not end-to-end integrity; backend interpretation and retry semantics require review |
| Untrusted upstream | Verified HTTPS, optional client TLS credentials, buffered response bounds and deadlines | Backend isolation, mTLS enforcement/authorization, certificate lifecycle and independent review |
| Stdio impersonation | Signed frames, live credential checks, scope policy, replay markers | Custom lockstep transport, no sandbox or full-duplex MCP; direct child inherits operator privileges |
| Data exfiltration | Block recognized patterns in raw/decoded JSON and selected metadata | Not comprehensive DLP; arbitrary encodings, split strings, semantic leakage and logs remain |
| Audit manipulation | JSON decision logs | Not immutable; incomplete coverage and potentially sensitive fields |
| Resource exhaustion | Connection, handler, aggregate and per-agent rate limits, bounded I/O and replay capacity | Sustained load, storage recovery, distributed admission and perimeter DoS defenses remain |

## Release blockers for production

Independently review authorization and parser compatibility; establish operational PKI and upstream isolation; measure resource limits under sustained load; establish durable state/backup, replay recovery and safe pruning; protect keys, logs and secrets; complete dependency and independent security review. Internal regression coverage does not close these production gates.

No claims of protection against arbitrary prompt injection, malicious models, compromised hosts, hardware attacks or distributed replay are made.

## Gateway transport update (increment 8)

Upstream TLS verifies the configured hostname/IP and certificate chain; optional client certificates enable mTLS when the server requires and authorizes them. Cleartext upstream is restricted to explicit literal loopback. External listeners require TLS. PKI compromise, certificate revocation/rotation, direct backend access, network isolation and deployment assurance remain residual risks. Local/CI validation passed at 5784d51 and final gateway baseline 8bbfe0f.

## Vault development-preview threat review

| Threat | Implemented preview defense | Residual risk |
|---|---|---|
| Ciphertext/key substitution | AES-GCM envelope and domain-bound context | KEK compromise, rollback, memory exposure |
| Secret policy bypass | Exact nondelegated identity, scope, HTTPS origin and operation grants | Trusted operator/backend semantics and indirect disclosure |
| Expired or retired credential | Authenticated expiry, pinned version, live HMAC lifecycle and one-use lease | Clock trust, state deletion/rollback, non-atomic dispatch |
| Provider impersonation | Verified pinned HTTPS import, bounded strict response | Trusted PKI/operator; no live provider revocation |
| Audit sink loss | Checked intent writes, latched on error, post-write rechecks | No durable collection or tamper-evident chain; sink can block |
| Resource loss | Individual record/parser limits, gateway admission bounds | Aggregate Vault storage, wrap quota enforcement, recovery, sustained load |

Preview excludes real credentials, provider-native leases, master rotation, multi-node state, and production deployment. Increment 010 GitHub CI succeeded at d2ad5d2 (44775885437); developer-local confirmation and independent review remain outstanding. Independent protocol/cryptographic review, explicit release approval and current dependency/toolchain checks remain open.
