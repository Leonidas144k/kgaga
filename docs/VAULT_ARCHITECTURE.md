# Kgaga Vault — cryptographic architecture

Status: increment 002 development foundation. Local immutable encrypted record storage; no key custody, secret-facing CLI or gateway injection yet.

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

Storage (increment 002): operator-only local Store API, explicit Init(path, vaultID) and Open(path, expectedVaultID), no implicit initialization, private 0700 directory and 0600 regular files. The manifest contains KGS1 and the 16-byte vault ID. Supply the expected identity and data key/key ID independently from trusted caller state. The manifest is not itself a cryptographic trust anchor. Each record path is a validated name, dot, fixed-width 20-digit version, and .kgv suffix; the file contains only the authenticated KGV1 envelope. No plaintext or raw DEK is written. Put encrypts in memory, writes a private temporary file, syncs it, then exclusively publishes with a hard link. Concurrent writers cannot replace the winning version. Get bounds reads and checks file type, permissions, path identity and the expected authenticated record context. An open store pins directory and manifest identity. Normal reopen with the same expected identity and key works; missing, replaced or corrupted state fails closed within the documented trust assumptions.

Only use supported POSIX local filesystems with hard links and protected hierarchy/ownership/ACLs; do not use shared or untrusted writable parents. The file checks are not race-proof against a malicious filesystem writer. File sync precedes publication but directory persistence, power-loss transactions and rollback protection are not established. Failure after publication can be ambiguous; never overwrite an existing version. A crash can leave encrypted .pending files or partial initialization; no automatic cleanup/recovery. Back up encrypted records and independent trusted metadata/key material together using a controlled offline process. No aggregate storage capacity limit or retention policy yet. Use only synthetic data until key custody and access policies are implemented.

Key hierarchy (increment 003): separate operator-controlled key encryption key (KEK), independent DEKs, separately domain-bound authenticated DEK wrapping, explicit key IDs and key rotation policy. Store wrapped DEKs beside ciphertext, never the plaintext KEK or DEK. No automated deletion or rotation before crash and recovery behavior is specified. External KMS integration remains a later increment.

Access and injection (increments 004–005): deny by default and bind decisions to verified identity, exact audience, service origin, method, path/tool, credential version and authorized injection target. No raw agent retrieval API by default. Revalidate live credentials at dispatch. Inspect responses for exact injected secret values as well as existing heuristics; this cannot guarantee protection against arbitrary upstream transformations or collusion.

Later: short-lived credentials, versioning, external secret managers, audit, adversarial testing and release review.

## Threat model and operational limits

Trust the operator, operating system and cryptographic randomness. A stolen ciphertext alone should not reveal secret plaintext without its data key. A stolen key can decrypt the matching record. Metadata is authenticated, not necessarily confidential. Ciphertext length reveals approximate secret length. Rollback protection, durable transaction recovery, key custody, storage capacity management, memory/runtime exposure, policy authorization and credential injection are future work. Exclusive publication and mode checks are implemented under protected-filesystem assumptions, not a sandbox. The foundation is not an operational secret manager and must not hold live credentials. Do not publish a production assurance claim based on primitive-level tests.
