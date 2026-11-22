# Kgaga Sentinel & Ledger v0.6.0 — development architecture

Status: increment 002, **development-preview single-host journal**. No runtime audit integration or Sentinel detector is implemented.

## Ledger scope (increment 001)

The new `internal/ledger` package accepts an already-validated `kgaga.vault.audit.v1` event, serializes a canonical JSON record and binds it into an HMAC-SHA256 chain. Each record contains `schema` (`kgaga.ledger.record.v1`), a random stream ID, monotonically increasing sequence, previous MAC, the original audit event and its MAC. The MAC is domain separated and binds the exact stream ID, sequence number, previous MAC and length-prefixed canonical event JSON. The verification key and stream ID must be known independently, not selected from the stream being verified.

The writer serializes concurrent appends on one process instance. Each successful call means only that the provided `io.Writer` accepted the full record. It does **not** mean fsync, persistent delivery, reliable recovery, log shipping or external checkpointing. A short write or I/O error latches the writer unavailable; ambiguous writes must not be replayed automatically. Invalid events fail before writing.

The verifier bounds each record to 16 KiB and the source audit event to 8 KiB, rejects incomplete rows, reordered/deleted/altered records, noncanonical JSON, wrong identities and MACs. A zero-record stream is valid genesis. It verifies **the observed prefix only**: deleting a valid trailing suffix or replacing the whole stream with a previously valid prefix is not detectable without an independently anchored expected `Head` (stream ID, sequence, MAC). A compromised HMAC key allows forging records. HMAC provides authenticity to key holders, not independent public verifiability or nonrepudiation.

Only synthetic events and short-lived test keys are suitable. No CLI, file/OS state, master-key custody, key rotation, persistent resume or checkpoint trust has been established. Existing Vault stderr auditing, gateway request handling, replay state and all authorization controls remain untouched.

## Increment 002 — single-writer synced journal

`InitJournal` creates a new private 0700 journal directory under a pre-existing private 0700 parent, plus private 0600 ledger.jsonl and exclusive 0700 writer lock. Journal appends must complete a file sync before the chain head advances. `OpenJournal` requires the independently retained HMAC key, stream ID and exact expected Head; it refuses truncated, mismatched or noncanonical records. Clean Close releases the writer lock. An ambiguous write, sync or integrity failure latches the writer and leaves its lock for manual offline inspection; never automatically delete a crash lock. Journal data is bounded to 64 MiB and checks inode, permissions and expected size during operations.

Limitations: a cooperative local POSIX lock does not stop privileged tampering or hostile writers; same-size mutations between checks may not be detected until next full verification. No durable independent checkpoint store, key custody, backup, recovery, trusted hardware, multi-host coordination, or runtime audit integration exists. A valid prefix remains acceptable if a caller supplies that prefix as its expected head. Storage durability depends on OS, filesystem and hardware guarantees.

## Planned next increments

1. Durable single-writer append/verification with explicit key custody and recovery semantics (no unsafe automatic resets).
2. Trusted checkpoint anchoring and restart continuity, backup and tamper-resistant retention.
3. Event normalization and safe integration with existing Vault audit, protecting credential dispatch on sink failures.
4. Sentinel detection rules for abnormal denials, replay, credential misuse and rate-limit signals, with bounded windows and false-positive controls.
5. Alert delivery, incident workflows, adversarial testing and release review.

Do not claim production-grade tamper evidence or reliable security alerts from this increment.
