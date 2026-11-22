# Kgaga v0.7.0 — Runtime Integration (Increment 001)

The first increment provides the **deliberately synthetic-only** `kgaga demo-sentinel --synthetic` command. This integrates existing components without enabling them on the Gateway: create private ephemeral Ledger journal/checkpoint files, record five synthetic denied credential attempts through `audit.Recorder` and `ledger.AuditBridge`, detect one advisory Sentinel threshold crossing, create an incident, acknowledge it, resolve it, verify the checkpoint and reconstruct the incident following clean journal reopen. The CLI prints an aggregate JSON summary with no credential values, key material, IDs or file paths. Both keys and all runtime files are kept only in an ephemeral temporary directory and cleaned up automatically.

This exercise does **not** instantiate a real AI agent, run the Gateway, issue a real credential, protect any live upstream, perform an external delivery, anchor a checkpoint outside its host, authenticate an operator, or test actual crash recovery. The trusted expected Head is kept only in the same process, and the separate checkpoint remains local. All operations are simulated and advisory. There is no automatic suspension or revocation.

Run:
```bash
go build -o kgaga ./cmd/kgaga
./kgaga demo-sentinel --synthetic
```

Expected output fields: `mode=synthetic`, `advisory_signals=1`, `incident_transitions=3`, `verified_ledger_records=8`, `recovered_state=resolved`, `notifications_sent=0`, `production_configured=false`.

## Next increments

- Read-only verified Ledger inspection with independent operator-provided trust material and expected Head, without automatically recovering locks
- Controlled single-host runtime wiring of audit and Sentinel, with safe startup and shutdown plus deliberate fail-closed behaviour
- Operator identity, checkpoint trust and documented recovery boundaries
- Isolated Gateway test with synthetic agents and safe failure injection

No production deployment, release tag or main merge is authorised.
