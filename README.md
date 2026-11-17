<div align="center">

# Pangolin 🛡️

**Cryptographic Identity & Security Gateway for Autonomous AI Agents & MCP Servers**

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

*The modern equivalent of foundational trust infrastructure, built for the era of AI agents.*

</div>

---

## What is Pangolin?

As companies deploy autonomous AI agents and Model Context Protocol (MCP) servers, they face a terrifying security gap: **shared hardcoded API keys, unmonitored tool calls, prompt-injection data exfiltration, and header/body desync attacks.**

**Pangolin** acts as a lightning-fast, zero-dependency Go gateway and CLI wrapper that solves this by introducing:
1. **Cryptographic Agent Passports** (Ed25519-signed short-lived tokens bounding agent identity, owner, and scoped permissions).
2. **MCP Desync & Protocol Confusion Protection** (Strict header-to-body JSON-RPC validation).
3. **Real-Time Secret Scrubbing** (Automatic regex redaction of AWS keys, GitHub PATs, OpenAI tokens, and PII).
4. **Local Stdio Wrapping** (`pangolin wrap`) for zero-friction local execution in Claude Desktop, Cursor, or Claude Code.

---

## Features

- **Sub-Millisecond Go Core:** Written in Go with single-binary distribution and zero runtime dependencies.
- **Ed25519 Cryptographic Signatures:** Asymmetric keypairs ensuring tamper-proof agent sessions.
- **JWKS Public Trust Endpoint:** Automatically exposes `/.well-known/jwks.json` so downstream APIs can verify agent passports dynamically.
- **YAML Policy Engine:** Granular path-based and tool-level allowlists/denylists (`pangolin.yaml`).
- **Immutable JSON Audit Logging:** Every allow/block decision is logged with timestamps and redaction telemetry.

---

## Installation & Quickstart

### 1. Initialize Root Keys & Policy
Run `init` to generate your root Ed25519 signing keys (`pangolin.key`, `pangolin.pub`) and a default `pangolin.yaml`:
```bash
pangolin init
