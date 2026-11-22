# Kgaga Sentinel & Ledger v0.6.0 — development architecture

Status: increment 004, **isolated Vault audit-to-Ledger adapter**. No default CLI Ledger configuration or Sentinel detector is implemented.

## Ledger scope (increment 001)

The new `internal/ledger` package accepts an already-validated `kgaga.vault.audit.v1` event, serializes a canonical JSON record and binds it into an HMAC-SHA256 chain. Each record contains `schema` (`kgaga.ledger.record.v1`), a random stream ID, monotonically increasing sequence, previous MAC, the original audit event and its MAC. The MAC is domain separated and binds the exact stream ID, sequence number, previous MAC and length-prefixed canonical event JSON. The verification key and stream ID must be known independently, not selected from the stream being verified.

The writer serializes concurrent appends on one process instance. Each successful call means only that the provided `io.Writer` accepted the full record. It does **not** mean fsync, persistent delivery, reliable recovery, log shipping or external checkpointing. A short write or I/O error latches the writer unavailable; ambiguous writes must not be replayed automatically. Invalid events fail before writing.

The verifier bounds each record to 16 KiB and the source audit event to 8 KiB, rejects incomplete rows, reordered/deleted/altered records, noncanonical JSON, wrong identities and MACs. A zero-record stream is valid genesis. It verifies **the observed prefix only**: deleting a valid trailing suffix or replacing the whole stream with a previously valid prefix is not detectable without an independently anchored expected `Head` (stream ID, sequence, MAC). A compromised HMAC key allows forging records. HMAC provides authenticity to key holders, not independent public verifiability or nonrepudiation.

Only synthetic events and short-lived test keys are suitable. No CLI, file/OS state, master-key custody, key rotation, persistent resume or checkpoint trust has been established. Existing Vault stderr auditing, gateway request handling, replay state and all authorization controls remain untouched.

## Increment 002 — single-writer synced journal

`InitJournal` creates a new private 0700 journal directory under a pre-existing private 0700 parent, plus private 0600 ledger.jsonl and exclusive 0700 writer lock. Journal appends must complete a file sync before the chain head advances. `OpenJournal` requires the independently retained HMAC key, stream ID and exact expected Head; it refuses truncated, mismatched or noncanonical records. Clean Close releases the writer lock. An ambiguous write, sync or integrity failure latches the writer and leaves its lock for manual offline inspection; never automatically delete a crash lock. Journal data is bounded to 64 MiB and checks inode, permissions and expected size during operations.

Limitations: a cooperative local POSIX lock does not stop privileged tampering or hostile writers; same-size mutations between checks may not be detected until next full verification. No durable independent checkpoint store, key custody, backup, recovery, trusted hardware, multi-host coordination, or runtime audit integration exists. A valid prefix remains acceptable if a caller supplies that prefix as its expected head. Storage durability depends on OS, filesystem and hardware guarantees.

## Increment 003 — separate authenticated checkpoint snapshot

`InitAnchoredJournal` creates an independent private checkpoint directory and uses **separate HMAC keys** for journal and checkpoint authentication. The checkpoint record contains the stream ID, sequence, journal MAC and a separately keyed witness MAC, stored in canonical bounded JSON. Each append synchronizes the journal before atomically publishing and synchronizing a new checkpoint snapshot. `OpenAnchoredJournal` requires the **independently retained expected Head** and verifies both layers before resuming.

Invalid checkpoint material, old snapshots, unsafe filesystem metadata, changed journal content, and unequal layers fail closed. An interruption after journal fsync but before checkpoint publication leaves an ambiguous state requiring explicit offline recovery; no automatic truncation, rollback, cleanup or permission downgrade. This is not an atomic cross-directory transaction. The checkpoint snapshot is authenticated but can itself be rolled back by a privileged attacker; rollback detection depends on independently retaining the latest expected Head in a genuinely separate trust domain. **Kgaga does not yet offer that external anchoring service**, authenticated backup, crash recovery procedures or production key custody. Separately named local directories do not guarantee isolated storage or administration. No runtime Vault audit integration.

## Increment 004 — checked Vault audit integration (programmatic opt-in)

The new `ledger.AuditBridge` implements `io.Writer` for the existing `audit.NewRecorder`. It accepts one bounded, canonical `kgaga.vault.audit.v1` JSON line per write, rejects unknown keys, duplicated keys, alternate encodings and non-event input, then calls `AnchoredJournal.Append`. A write succeeds **only after the local journal and separate checkpoint both complete**. A failure latches the bridge and the recorder; no fallback to stderr, no automatic replay and no bypass of Vault's existing dispatch/release auditing. Concurrency is serialized.

`VaultGateway.WithAuditRecorder(rec)` returns a *new* broker bound to an explicitly supplied recorder, without modifying an already-serving handler. The existing Vault request/response handling still calls `audit.Recorder.Record` for intent and response release. The integration test constructs a real TLS Vault handler with this alternate recorder and verifies that deliberate journal tampering produces HTTP 503 before a credential can be dispatched.

**Scope restriction:** this is an opt-in *programmatic integration* and test foundation, not a new CLI flag or a default runtime change. The current `kgaga proxy` CLI continues to use the existing structured stderr sink. Separate operator configuration, key custody, trusted checkpoint input, lifecycle, runtime cleanup, recovery and deployment guidance remain unimplemented. Because `AnchoredJournal` holds per-process locks and retains incomplete commits for offline inspection, a restart must not invent or reset checkpoint state. No external trusted checkpoint service. Use synthetic events only.

## Planned next increments

1. Durable single-writer append/verification with explicit key custody and recovery semantics (no unsafe automatic resets).
2. Trusted checkpoint anchoring and restart continuity, backup and tamper-resistant retention.
3. Event normalization and safe integration with existing Vault audit, protecting credential dispatch on sink failures.
4. Sentinel detection rules for abnormal denials, replay, credential misuse and rate-limit signals, with bounded windows and false-positive controls.
5. Alert delivery, incident workflows, adversarial testing and release review.

Do not claim production-grade tamper evidence or reliable security alerts from this increment.
