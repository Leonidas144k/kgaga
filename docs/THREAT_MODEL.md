# Threat model — initial identity development preview

Scope: source review of 662eafd, not an independent penetration test or certification. Threats include malicious agents, compromised holder keys, network attackers, hostile upstream/MCP servers, privileged operator error and state loss.

## Assets and assumptions

Protect issuer and holder keys, enrolled identities and permissions, credential lifetimes, revocation/retirement/suspension records, replay state, upstream data and audit events. The operator, OS, clock, local filesystem and configured upstream are trusted in current tests. Keep services isolated, use synthetic data and do not expose listeners publicly. A compromised privileged operator or issuer is outside the current protection model.

## Threat register

| Threat | Current control | Residual risk / required work |
| --- | --- | --- |
| Forged, expired or wrong-audience passport | Ed25519, strict claims, trusted kid, exact audience | Independent JWT/parser review; issuer compromise |
| Stolen passport | Registered holder thumbprint and signed HTTP request | Full captured proof can race original; compromised key impersonates holder |
| Replayed proof | Freshness checks and exclusive nonce marker | Unbounded markers, disk exhaustion, clock rollback, multiple hosts, state rollback |
| Unauthorized registration | Operator approval and new CLI challenge proof | No independent identity/workload attestation; older registrations not retroactively checked |
| Excess delegation | Same owner and audience, subset, expiry bound, parent checks | Grant reuse, no independent grant revocation; test gateway lifecycle |
| Compromised issuer | Explicit trust and permanent retirement | Manual rotation; state trust and in-flight requests; no HSM |
| State loss or replacement | Running process checks directory identity; deny on errors | Restart cannot establish trusted history; backups and rollback protection required |
| Policy boundary ambiguity | First matching path prefix / scope and tool checks | Segment boundaries, method semantics, overlapping rules and policy schema need hardening |
| Protocol confusion | Initial JSON-RPC and header/body checks | Parser ambiguity, route classification and unsupported transports need strict handling |
| Request transformation | Signed selected inbound fields | Unbound forwarding headers and hop-by-hop behavior; verify downstream semantics |
| Untrusted upstream | Configured HTTP(S) target | No comprehensive response bounds, streaming deadlines, isolation or authenticated channel enforcement |
| Stdio impersonation | Signed frames, live credential checks, scope policy, replay markers | Custom lockstep transport, no sandbox or full-duplex MCP; direct child inherits operator privileges |
| Data exfiltration | Limited regex redaction | Not comprehensive DLP; encoding, tool output, headers and semantic leakage remain |
| Audit manipulation | JSON decision logs | Not immutable; incomplete coverage and potentially sensitive fields |
| Resource exhaustion | Request body, header and read limits | Rate limits, bounded state, response limits and denial-of-service testing needed |

## Release blockers for production

Harden route and method policy semantics and validate policy configuration; reject ambiguous protocol inputs and transformations; enforce safe authenticated transports and isolate upstream; establish resource bounds, durable state/backup and recovery; protect logs and secrets; complete independent security review. The production release must have explicit acceptance criteria and evidence for each. The identity preview does not close these blockers.

No claims of protection against arbitrary prompt injection, malicious models, compromised hosts, hardware attacks or distributed replay are made.
