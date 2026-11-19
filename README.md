# Kgaga 🛡️
Cryptographic Identity & Security Gateway for Autonomous AI Agents & MCP Servers

The modern equivalent of foundational trust infrastructure, built for the era of AI agents.

## What is Kgaga?
As companies deploy autonomous AI agents and Model Context Protocol (MCP) servers, they face a terrifying security gap: shared hardcoded API keys, unmonitored tool calls, prompt-injection data exfiltration, and header/body desync attacks.

Kgaga acts as a lightning-fast, single-binary Go gateway and CLI wrapper that addresses parts of this by introducing:
1. **Cryptographic Agent Passports** (Ed25519-signed short-lived tokens bounding agent identity, owner, and scoped permissions).
2. **MCP Desync & Protocol Confusion Protection** (Strict header-to-body JSON-RPC validation).
3. **Real-Time Secret Scrubbing** (Automatic regex redaction of AWS keys, GitHub PATs, OpenAI tokens, and bearer credentials).
4. **Local Stdio Wrapping** (`kgaga wrap`) for experimental local execution in Claude Desktop, Cursor, or Claude Code.

## Features
- **Go Core:** Written in Go with single-binary distribution and zero runtime dependencies.
- **Ed25519 Cryptographic Signatures:** Asymmetric keypairs ensuring signed agent credentials.
- **JWKS Public Trust Endpoint:** Automatically exposes `/.well-known/jwks.json` so downstream APIs can verify agent passports dynamically.
- **YAML Policy Engine:** Granular path-based and tool-level allowlists/denylists (`kgaga.yaml`).
- **JSON Audit Logging:** The HTTP gateway logs security decisions with timestamps and redaction telemetry; logs are not tamper-evident.

## Installation for Users

### Option A: Download Pre-Built Binaries

Kgaga binaries will be published with the first rebranded release. The v0.1.0 Pangolin binaries are historical; renaming a binary does not migrate its configuration.

1. Open the [GitHub Releases](https://github.com/Leonidas144k/kgaga/releases) page.
2. Download the binary that matches your operating system (Linux, macOS, or Windows) and CPU architecture.
3. Extract the download if it is an archive, then rename the executable to `kgaga` on Linux or macOS, or `kgaga.exe` on Windows.
4. Add the executable to your `PATH` so you can run `kgaga` from any directory.

**Linux and macOS**

From the directory containing the downloaded executable, run:

```bash
sudo mkdir -p /usr/local/bin
sudo install -m 0755 ./kgaga /usr/local/bin/kgaga
```

**Windows**

Move `kgaga.exe` to a folder such as `C:\Tools\Kgaga`, add that folder to your user `Path` environment variable, and open a new PowerShell window.

### Option B: Build From Source

Install Git and Go, then clone the repository and build the CLI.

**Linux and macOS**

```bash
git clone https://github.com/Leonidas144k/kgaga.git
cd kgaga
go build -o kgaga ./cmd/kgaga
```

Install the compiled binary:

```bash
sudo mkdir -p /usr/local/bin
sudo install -m 0755 ./kgaga /usr/local/bin/kgaga
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/Leonidas144k/kgaga.git
Set-Location kgaga
go build -o kgaga.exe ./cmd/kgaga
```

Move the compiled executable to a folder on your `Path`, as described in Option A.

## Quick Start

The examples below assume `kgaga` is on your `PATH`. To run it directly from the directory containing the executable, replace `kgaga` with `./kgaga` on Linux or macOS, or `.\kgaga.exe` in PowerShell.

### Mint an Agent Passport

Run `kgaga init` and then `kgaga revocations-init` once in a dedicated new directory before these examples. For an existing v2 development installation, only initialize the revocation store once; do not regenerate keys. Generate a short-lived signed token bound to an explicit service audience, an agent, an owner, and permission scopes. Protect the private signing key; its holder can mint any identity or scope.

**Linux and macOS (Bash)**

```bash
TOKEN=$(kgaga mint \
  --agent "support-bot" \
  --owner "ops@company.com" \
  --scopes "mcp:tool:search,db:read" --audience "support-api")
printf '%s' "$TOKEN" | kgaga verify --audience "support-api"
```

**Windows (PowerShell)**

```powershell
$TOKEN = kgaga mint --agent "support-bot" --owner "ops@company.com" --scopes "mcp:tool:search,db:read" --audience "support-api"
$TOKEN | kgaga verify --audience "support-api"
```

Replace the example agent name, owner, and scopes with the values required for your agent.

### Start an audience-bound gateway

```bash
kgaga proxy --listen 127.0.0.1:8080 --target http://localhost:3000 --audience support-api
```

Use a distinct service identifier per trust boundary, and use the same audience for issuance and gateway verification. Audiences are explicit identifiers, not inferred from untrusted HTTP headers. Passports use Ed25519, a key thumbprint, a random credential ID, and mandatory time claims; default TTL is 15 minutes, maximum 1 hour. Unique IDs are not replay protection. Single-host passport revocation is now enforced by the CLI and audience-bound gateway. Key rotation, proof of possession, distributed revocation, and authenticated stdio remain future work. The gateway strips the passport header before forwarding, and sets verified identity headers from signed claims; upstream services must only trust these headers on an authenticated, isolated gateway connection. Use only in controlled testing, not production.

### Revoke a passport

The verified claims returned by `kgaga verify` include a `jti` field. An authorized operator can invalidate that identifier:

```bash
kgaga revoke --id <jti>
```

Use the actual 32-character lowercase hexadecimal ID. Subsequent CLI verification fails, and gateway requests using the revoked passport return HTTP 403. A missing or replaced store fails closed (HTTP 503 on the gateway). All three commands (`verify`, `proxy`, and `revoke`) must use the same local directory, configurable via `--revocations`. The default is `kgaga-revocations` relative to the working directory.

Keep the store and its parent directory under trusted operator control, backed up, and outside source control. Do not recreate lost revocation state; restore it from trusted backup or retire the affected credentials. Records are retained indefinitely in this increment. This single-host design is not tamper-proof, does not synchronize across hosts, cannot cancel already admitted requests, and does not prevent replay of an unrevoked bearer token.

## Migration from Pangolin v0.1

This is an early-stage security prototype, not production-ready. The stdio wrapper does not authenticate callers or enforce full passport scopes. The current CLI requires v2 passports issued by `kgaga-ca`, with a key thumbprint and explicit audience. Legacy passports are rejected; reissue them before upgrading. The legacy internal verifier is retained for regression coverage, not exposed as a CLI fallback. The HTTP input remains `X-Agent-Passport`. Upstream identity headers are `X-Kgaga-Verified-Agent` / `X-Kgaga-Agent-Owner`; the legacy Pangolin equivalents are also emitted for compatibility. The legacy redaction marker is also preserved. These are not trademark or identity verification claims.

Before switching branches, back up your existing key files and policy securely outside the repository. To preserve an existing identity, copy the matching private and public keys to `kgaga.key` (mode 0600) and `kgaga.pub` and migrate your policy to `kgaga.yaml`. Do not run init over an existing identity. The tracked legacy `pangolin.pub` is historical, not a trusted default for new installations. For a new installation, run `kgaga init` in a dedicated directory. Never commit private keys or bearer tokens.

The Go module now uses `github.com/Leonidas144k/kgaga`; the GitHub repository has been renamed. Planned website: https://kgaga.afrosoft.co.za.

See [the development roadmap](docs/roadmap.md) for planned security work.
