# Kgaga Vault — cryptographic architecture

Status: increment 001 development foundation; no persistent vault, secret-facing CLI or gateway injection is implemented yet.

## Goal and separation of duties

Identity authenticates an agent; Gateway authorizes its actions; Vault will hold credentials behind the gateway's trust boundary. A passport or holder key must never serve as a vault encryption key. Agents must not be able to select arbitrary secret names, destinations or injection headers. The operator configures those bindings. Future injection must occur after policy checks, only to the authorized verified TLS origin, with no redirect following and no credential-bearing output returned to agents.

## Implemented record primitive (format 1)

- AES-256-GCM via Go's standard library, 32-byte randomly generated data keys, 12-byte cryptographically random nonces and 16-byte authentication tags.
- Generate a new independent data encryption key (DEK) for each immutable record version. Key generation uses crypto/rand. The primitive accepts explicit data keys for decrypting records; it does not enforce their lifecycle or uniqueness.
- Binary encoding: ASCII KGV1 followed by a 12-byte nonce and GCM ciphertext/tag. Plaintext size 1 to 65,536 bytes. No compression or algorithm negotiation.
- Associated authenticated data: ASCII kgaga-vault:record:v1, one zero byte, ASCII KGV1, 16-byte vault identifier, 16-byte data key identifier, 8-byte big-endian positive record version, one-byte name length and exact name bytes. Names contain lowercase ASCII letters, digits, underscore or hyphen (1–64 bytes).
- Caller supplies expected metadata from trusted record context. Substituted vault, name, version or key ID, wrong key and modified ciphertext fail authentication. No plaintext is returned following verification failure.
- This primitive does not protect against replacement with an old valid record and its matching metadata, a compromised host, or a party holding the data key. No secure memory-erasure guarantee in Go.

## Planned storage and key hierarchy

Storage (increment 002): design immutable encrypted records and bounded parsing, explicit initialization, restricted directory/file permissions, exclusive atomic publication, restart tests, fail-closed error behavior and backup constraints. No plaintext at rest. Until key custody is implemented, exercise only synthetic data with ephemeral caller-owned data keys.

Key hierarchy (increment 003): separate operator-controlled key encryption key (KEK), independent DEKs, separately domain-bound authenticated DEK wrapping, explicit key IDs and key rotation policy. Store wrapped DEKs beside ciphertext, never the plaintext KEK or DEK. No automated deletion or rotation before crash and recovery behavior is specified. External KMS integration remains a later increment.

Access and injection (increments 004–005): deny by default and bind decisions to verified identity, exact audience, service origin, method, path/tool, credential version and authorized injection target. No raw agent retrieval API by default. Revalidate live credentials at dispatch. Inspect responses for exact injected secret values as well as existing heuristics; this cannot guarantee protection against arbitrary upstream transformations or collusion.

Later: short-lived credentials, versioning, external secret managers, audit, adversarial testing and release review.

## Threat model and operational limits

Trust the operator, operating system and cryptographic randomness. A stolen ciphertext alone should not reveal secret plaintext without its data key. A stolen key can decrypt the matching record. Metadata is authenticated, not necessarily confidential. Ciphertext length reveals approximate secret length. Rollback protection, durable transaction recovery, key custody, cross-process storage concurrency, memory/runtime exposure, permissions enforcement, policy authorization and credential injection are future work. The foundation is not an operational secret manager and must not hold live credentials. Do not publish a production assurance claim based on primitive-level tests.
