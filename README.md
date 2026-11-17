# Pangolin 🛡️
Cryptographic Identity & Security Gateway for Autonomous AI Agents & MCP Servers

The modern equivalent of foundational trust infrastructure, built for the era of AI agents.

## What is Pangolin?
As companies deploy autonomous AI agents and Model Context Protocol (MCP) servers, they face a terrifying security gap: shared hardcoded API keys, unmonitored tool calls, prompt-injection data exfiltration, and header/body desync attacks.

Pangolin acts as a lightning-fast, zero-dependency Go gateway and CLI wrapper that solves this by introducing:
1. **Cryptographic Agent Passports** (Ed25519-signed short-lived tokens bounding agent identity, owner, and scoped permissions).
2. **MCP Desync & Protocol Confusion Protection** (Strict header-to-body JSON-RPC validation).
3. **Real-Time Secret Scrubbing** (Automatic regex redaction of AWS keys, GitHub PATs, OpenAI tokens, and PII).
4. **Local Stdio Wrapping** (`pangolin wrap`) for zero-friction local execution in Claude Desktop, Cursor, or Claude Code.

## Features
- **Sub-Millisecond Go Core:** Written in Go with single-binary distribution and zero runtime dependencies.
- **Ed25519 Cryptographic Signatures:** Asymmetric keypairs ensuring tamper-proof agent sessions.
- **JWKS Public Trust Endpoint:** Automatically exposes `/.well-known/jwks.json` so downstream APIs can verify agent passports dynamically.
- **YAML Policy Engine:** Granular path-based and tool-level allowlists/denylists (`pangolin.yaml`).
- **Immutable JSON Audit Logging:** Every allow/block decision is logged with timestamps and redaction telemetry.

## Installation for Users

### Option A: Download Pre-Built Binaries (Recommended)
Head over to the [GitHub Releases](https://github.com/Leonidas144k/pangolin/releases) page and download the binary for your operating system (Linux, macOS, or Windows).

### Option B: Build From Source
If you have Go installed, you can clone and build the binary directly:
```bash
git clone [https://github.com/Leonidas144k/pangolin.git](https://github.com/Leonidas144k/pangolin.git)
cd pangolin
go build -o pangolin ./cmd/pangolin### 2. Mint an Agent Passport

Generate a short-lived, cryptographically signed token bound to specific agent capabilities:
```bash
TOKEN=$(pangolin mint --agent "support-bot" --owner "ops@company.com" --scopes "mcp:tool:search,db:read")
echo $TOKEN
