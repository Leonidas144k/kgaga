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

1. Open the [GitHub Releases](https://github.com/Leonidas144k/pangolin/releases) page.
2. Download the binary that matches your operating system (Linux, macOS, or Windows) and CPU architecture.
3. Extract the download if it is an archive, then rename the executable to `pangolin` on Linux or macOS, or `pangolin.exe` on Windows.
4. Add the executable to your `PATH` so you can run `pangolin` from any directory.

**Linux and macOS**

From the directory containing the downloaded executable, run:

```bash
sudo mkdir -p /usr/local/bin
sudo install -m 0755 ./pangolin /usr/local/bin/pangolin
```

**Windows**

Move `pangolin.exe` to a folder such as `C:\Tools\Pangolin`, add that folder to your user `Path` environment variable, and open a new PowerShell window.

### Option B: Build From Source

Install Git and Go, then clone the repository and build the CLI.

**Linux and macOS**

```bash
git clone https://github.com/Leonidas144k/pangolin.git
cd pangolin
go build -o pangolin ./cmd/pangolin
```

Install the compiled binary:

```bash
sudo mkdir -p /usr/local/bin
sudo install -m 0755 ./pangolin /usr/local/bin/pangolin
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/Leonidas144k/pangolin.git
Set-Location pangolin
go build -o pangolin.exe ./cmd/pangolin
```

Move the compiled executable to a folder on your `Path`, as described in Option A.

## Quick Start

The examples below assume `pangolin` is on your `PATH`. To run it directly from the directory containing the executable, replace `pangolin` with `./pangolin` on Linux or macOS, or `.\pangolin.exe` in PowerShell.

### Mint an Agent Passport

Generate a short-lived, cryptographically signed token bound to an agent, an owner, and specific permission scopes.

**Linux and macOS (Bash)**

```bash
TOKEN=$(pangolin mint \
  --agent "support-bot" \
  --owner "ops@company.com" \
  --scopes "mcp:tool:search,db:read")
echo "$TOKEN"
```

**Windows (PowerShell)**

```powershell
$TOKEN = pangolin mint --agent "support-bot" --owner "ops@company.com" --scopes "mcp:tool:search,db:read"
$TOKEN
```

Replace the example agent name, owner, and scopes with the values required for your agent.
