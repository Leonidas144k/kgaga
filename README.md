# Kgaga 🛡️
Cryptographic Identity & Security Gateway for Autonomous AI Agents & MCP Servers

The modern equivalent of foundational trust infrastructure, built for the era of AI agents.

**Development preview — not for production or Internet-facing deployment.** See [security policy](SECURITY.md), [threat model](docs/THREAT_MODEL.md), [architecture](docs/ARCHITECTURE.md) and [release gates](docs/RELEASE_CHECKLIST.md).

## What is Kgaga?
As companies deploy autonomous AI agents and Model Context Protocol (MCP) servers, they face a terrifying security gap: shared hardcoded API keys, unmonitored tool calls, prompt-injection data exfiltration, and header/body desync attacks.

Kgaga acts as a lightning-fast, single-binary Go gateway and CLI wrapper that addresses parts of this by introducing:
1. **Cryptographic Agent Passports** (Ed25519-signed short-lived tokens bounding agent identity, owner, and scoped permissions).
2. **MCP Desync & Protocol Confusion Protection** (Initial header-to-body JSON-RPC validation; full protocol hardening is pending).
3. **Bidirectional Secret-Pattern Inspection** (Block recognized AWS, GitHub, OpenAI-style and bearer credential patterns; not comprehensive DLP).
4. **Authenticated Stdio Wrapping** (`kgaga wrap`) for a restricted signed-frame development transport; a client adapter is required.

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

Run `kgaga init`, `kgaga revocations-init`, `kgaga agents-init`, `kgaga replay-init`, `kgaga keys-init`, and `kgaga key-trust --public kgaga.pub` once in a dedicated new directory. Existing installations must initialize only missing stores as part of an intentional first-time migration, not recreate lost state or regenerate keys. Register an agent before minting:

```bash
kgaga key-generate --out /secure/agent-holder
CHALLENGE=$(kgaga agent-challenge --agent support-bot)
# Run the following signing command on the agent host with its private key.
ENROLMENT=$(kgaga agent-sign-enrolment --holder-key /secure/agent-holder/kgaga.key --challenge "$CHALLENGE" --agent support-bot --owner ops@company.com --scopes mcp:tool:search,db:read --audiences support-api)
# Return only the public key and enrolment signature to the trusted operator.
kgaga agent-register --agent support-bot --owner ops@company.com --scopes mcp:tool:search,db:read --audiences support-api --holder-public /secure/agent-holder/kgaga.pub --challenge "$CHALLENGE" --enrolment-proof "$ENROLMENT"
```

Generate a short-lived signed token bound to an explicit service audience, an agent, an owner, and permission scopes. Protect the signing key and state; a key holder can sign claims outside the CLI, so registry checks at verification are mandatory.

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

### HTTP policy v2 (gateway development branch)

Existing policy files with version "1" will no longer load. Back up the policy outside source control, set `version: "2"`, and explicitly add `allowed_methods` to every HTTP rule. Review scopes rather than automatically granting old methods. The bundled defaults permit GET/HEAD for the database read rule and POST for the payments rule. The most specific segment-boundary prefix wins; a denial never falls back to a broader rule. Duplicate winning rules deny; method names are exact and `deny_methods` overrides the winning rule's allowlist. No allowlist means no access.

Routes are restricted to literal ASCII unreserved path segments, without percent escapes, duplicate slashes, trailing slash aliases, dot segments or matrix parameters. Upstream targets must be origin URLs without a base path or query. MCP is selected by the exact /mcp route and POST only; nonempty MCP headers elsewhere and common alternate routing/method override headers are rejected. Use a case-sensitive upstream with matching path semantics; this is not full HTTP/MCP integrity or policy schema validation. Query/body-based method overrides and other upstream-specific routing conventions must be disabled by the operator.

### Validate policy configuration

```bash
kgaga policy-check --config kgaga.yaml
```

The policy checker and gateway require one YAML document of at most 128 KiB, with explicit `version`, `redact_secrets`, `mcp` and `rules` fields. Both MCP lists and every rule's `path_prefix`, `allowed_scopes`, `allowed_methods` and `deny_methods` fields are required. Unknown or duplicate fields, aliases, anchors, merge keys, explicit tags, scalar coercion, invalid paths, duplicate routes and invalid/duplicate list items are rejected. HTTP rule method/scope lists must be nonempty; use `rules: []` to deny all HTTP routes. An empty MCP tool allowlist denies all tool calls, including admin scope; an explicit sole "*" entry permits any tool not denied, subject to passport scopes. Denials take precedence within the winning rule. Other MCP method authorization remains unchanged. The gateway validates and snapshots its configuration at startup; policy changes require restart. Select a policy file with `proxy --config <file>`.

### Restricted MCP HTTP preview

Only POST /mcp without query parameters and application/json (optional UTF-8 charset) is inspected. A single JSON-RPC 2.0 request is required. Supported methods: initialize, ping, tools/list, tools/call and notifications/initialized. All other methods and batches are rejected. Requests require a nonempty string ID or safe-range integer ID; notifications/initialized must omit it. Params, when present, must be an object. Tool calls require a literal ASCII tool name and object arguments/_meta when present. Passport scope checks and the tool allowlist still apply.

The parser rejects duplicate keys (including case-folded aliases as detected by Go strings.ToLower), unexpected envelope fields, invalid UTF-8, replacement characters, trailing JSON, depth over 32 and excessive token count. Body size remains 1 MiB. Optional compatibility method/name headers must match the body; redundant Mcp-Name is removed before forwarding. Duplicate headers, encoded bodies, trailers and unsupported connection options are rejected. With redact_secrets enabled, MCP requests matching existing secret patterns are blocked rather than rewritten after authorization. This is intentionally restrictive, not full MCP conformance or comprehensive DLP; method-specific schemas, negotiation/state, streaming, server responses and stdio security remain incomplete.

### Bounded request and response inspection

The HTTP gateway is no longer a transparent reverse proxy. It forwards only selected content/MCP headers and trusted identity headers, with a fixed Accept value. Client authorization, cookies and arbitrary headers are not forwarded. Upstream response headers are restricted to content type and selected MCP metadata; redirects, partial responses, encodings, trailers and streaming are unsupported. Nonempty payloads must be UTF-8 application/json or text/plain. Bodies are capped at 1 MiB in each direction; upstream response headers are capped at 32 KiB, response header wait at 10 seconds and total exchange at 30 seconds. HTTP MCP responses require a JSON-RPC 2.0 result/error with matching ID and HTTP 200, or an empty 202/204 for the supported notification. The HTTP exchange is buffered and inspected before any upstream bytes are sent to the client. Current credential lifecycle is checked again before response release; already dispatched side effects cannot be undone.

The existing `redact_secrets: true` setting now blocks recognized secret patterns in request and response payloads, JSON-decoded keys/strings, request query and selected metadata rather than rewriting signed data. The authenticated stdio transport uses the same payload scanner. Patterns are heuristic and do not recognize all credentials, arbitrary encodings, split strings, attachments or indirect leakage. Setting the flag false disables secret-pattern checks, not text/JSON validation or size bounds. This development-only restriction may break existing REST and MCP clients. Upstream TLS/mTLS policy, admission concurrency, complete protocol schemas and response streaming remain outstanding.

### Start an audience-bound gateway (isolated test environment only)

```bash
kgaga proxy --listen 127.0.0.1:8080 --target http://localhost:3000 --audience support-api
```

Use a distinct service identifier per trust boundary, and use the same audience for issuance and gateway verification. Audiences are explicit identifiers, not inferred from untrusted HTTP headers. Passports use Ed25519, a key thumbprint, a random credential ID, and mandatory time claims; default TTL is 15 minutes, maximum 1 hour. Unique IDs are not replay protection. Single-host passport revocation is now enforced by the CLI and audience-bound gateway. Local operator-controlled key rotation is supported. Holder-bound HTTP request proofs and single-host replay protection are implemented; authenticated stdio is available in restricted lockstep mode; distributed revocation remains future work. The gateway strips the passport header before forwarding, and sets verified identity headers from signed claims; upstream services must only trust these headers on an authenticated, isolated gateway connection. Use only in controlled testing, not production.

### Revoke a passport

The verified claims returned by `kgaga verify` include a `jti` field. An authorized operator can invalidate that identifier:

```bash
kgaga revoke --id <jti>
```

Use the actual 32-character lowercase hexadecimal ID. Subsequent CLI verification fails, and gateway requests using the revoked passport return HTTP 403. A missing or replaced store fails closed (HTTP 503 on the gateway). All three commands (`verify`, `proxy`, and `revoke`) must use the same local directory, configurable via `--revocations`. The default is `kgaga-revocations` relative to the working directory.

Keep the store and its parent directory under trusted operator control, backed up, and outside source control. Do not recreate lost revocation state; restore it from trusted backup or retire the affected credentials. Records are retained indefinitely in this increment. This single-host design is not tamper-proof, does not synchronize across hosts, cannot cancel already admitted requests, and does not itself prevent replay. Holder proofs and the separate replay store provide the HTTP replay check.

### Inspect and suspend an agent

```bash
kgaga agent-inspect --agent support-bot
kgaga agent-suspend --agent support-bot
```

Mint, verify and the audience-bound HTTP gateway require a registered agent with the exact owner, an allowed audience and a subset of allowed scopes. Suspension is permanent for that ID in this increment, blocks existing passports and prevents new issuance through the CLI. There is no resume or editing command: issue a fresh identity when needed. Use the same registry directory for all commands (default `kgaga-agents`, override with `--registry`). The store is designed for a trusted operator on a single host with hard-link support; protect all directories, never commit them, and do not recreate lost state. A running gateway detects missing/replaced registry directories. There is no distributed synchronization, independent owner proof, power-loss guarantee or cancellation of in-flight requests. The low-level signer remains a signing primitive; it does not authorize agents.

### Signing key rotation

Trust is explicit and fail closed. Bootstrap an existing installation only once using `kgaga keys-init` and `kgaga key-trust --public kgaga.pub`; do not recreate missing state after data loss. Use `--trust` to select the same trusted directory (default `kgaga-trust`) for mint, verify, proxy and key administration. The old key remains valid until explicitly retired.

```bash
kgaga key-generate --out /secure/new-key-directory
NEW_KID=$(kgaga key-trust --public /secure/new-key-directory/kgaga.pub)
kgaga keys-list
kgaga mint --signing-key /secure/new-key-directory/kgaga.key --agent support-bot --owner ops@company.com --scopes db:read --audience support-api
# After migrating issuers and allowing outstanding passports to expire,
# or immediately on compromise, permanently retire the old kid:
kgaga key-retire --kid OLD_KID
```

Replace placeholders with actual paths and the old key's thumbprint. Keep all private keys outside version control. JWKS is read from live trusted records and excludes retired keys; downstream caches and already admitted requests are outside this guarantee. Retirement is permanent through the CLI; no automatic active-key selection, distributed synchronization, HSM, tamper-proof store or verified power-loss durability is provided. This requires a local filesystem with hard-link support and trusted operator control over state and its parent directory. Do not delete retirement markers or restore stale state. The old unauthenticated stdio wrapper has been removed.

### Holder-bound requests (development protocol)

Generate an independent agent key on the agent host, and register only its public PEM. Existing registrations without a holder key cannot issue or use passports; register a fresh ID rather than editing existing immutable records. Earlier unbound passports are denied. The issuer signs a confirmation thumbprint (`cnf.jkt`); gateway and CLI compare it against the registry. The agent keeps its private key separate from the issuer. The `verify` command inspects credential validity and binding but does not authenticate a live request.

Initialize a dedicated replay directory with `kgaga replay-init` (only once; never recreate lost state). For each request, sign a fresh proof using the exact inbound method, path/query, request bytes and supported header values. Pass the passport via stdin:

```bash
PROOF=$(printf '%s' "$TOKEN" | kgaga proof --holder-key /secure/agent-holder/kgaga.key --method GET --target /api/db)
# Send the passport in X-Agent-Passport and the fresh proof in X-Kgaga-Proof.
```

Use TLS; avoid exposing secrets in command arguments, logs or URLs. `--body-file`, `--content-type`, `--mcp-version`, `--mcp-method`, and `--mcp-session` bind the relevant inbound values. Encoded bodies and ambiguous headers are rejected. Proofs are `v1.timestamp.nonce.signature`: decimal Unix seconds, 16 random bytes in lowercase hex, and base64url Ed25519 signature without padding. The signed message is Go `encoding/json.Marshal` of the string array `["kgaga-request-proof-v1", timestamp, nonce, base64url(SHA256(passport)), method, origin-form target, content-type, mcp-version, mcp-method, mcp-session, base64url(SHA256(body))]`. This is a Kgaga development protocol, not RFC 9449 DPoP or HTTP Message Signatures. The gateway permits 30 seconds of age and 5 seconds of future clock skew, records each valid proof nonce exclusively in the local replay directory before policy evaluation, and strips the proof before forwarding. A replay is rejected even after a normal restart; markers are retained indefinitely. Use the same protected `--replay` store for all gateways sharing a trust boundary on this host. Distributed replay prevention, pruning, power-loss durability, full HTTP header integrity, transport security, and independent review remain outstanding. A captured complete fresh request could still race the legitimate request. Do not use in production.

### Challenge-based enrolment

The trusted operator creates a random 256-bit challenge tied to the exact proposed agent ID. It expires after five minutes and is consumed once with an exclusive filesystem marker. The agent signs a domain-separated statement containing the challenge, agent ID, owner, exact scope and audience lists, and holder public-key thumbprint. The signed encoding is Go `encoding/json.Marshal` of the array `["kgaga-enrolment-v1", challenge, agent, owner, scopes, audiences, holder_jkt]`, where scopes/audiences are ordered arrays of strings. The signature is unpadded base64url Ed25519. The operator must independently approve the owner, key and permissions and authenticate the exchange; proof of key possession is not independent identity, hardware, software, model, or workload attestation.

Use the same protected registry directory for challenge issuance and registration. Missing, expired, mismatched or consumed challenges are rejected. A consumed challenge is never retried if registration fails; use a new one. Records and markers survive ordinary process restarts and are retained indefinitely in this development increment. The holder private key never needs to leave the agent host. Existing holder-bound registrations remain valid and are not retroactively attested; to require this enrolment for all identities, suspend old IDs and register new ones. There is no public enrollment service or distributed challenge ledger. Operator filesystem access remains the trust boundary.

### One-hop issuer-mediated delegation

An enrolled parent with a passport carrying `kgaga:delegate` can sign a grant for a different enrolled child under the same owner and audience. The child receives only an exact subset of parent scopes, excluding `kgaga:delegate`, and must have a different holder key. The grant signs the parent passport digest, child ID, owner, ordered scope list, audience, child key thumbprint and absolute Unix expiry. The expiry must not exceed the parent's expiry. The trusted issuer explicitly issues the child using `delegate`; the parent signs using `delegate-sign`. Both commands read the parent passport from stdin. See the isolated CLI lifecycle script for runnable examples. Do not expose tokens or private keys in logs or source control.

Delegated credentials use the distinct JWT type `kgaga-delegated+jwt`. They embed the original signed parent passport and grant signature to allow live revalidation of parent trust, revocation, registered holder, permissions and grant constraints in the CLI and HTTP gateway. Older builds reject this type. A parent passport is credential material; protect the child passport accordingly. Revoking or suspending the parent or retiring its signing key blocks subsequent delegated requests. Grants may be reused by the trusted issuer until expiry (revoking one child passport does not revoke the grant; revoke the parent to disable all grants). No nested delegation, cross-owner delegation, cross-audience delegation, remote issuance API or individual grant revocation exists yet. Direct issuance remains a separate trusted operator action. This is a development protocol, not OAuth token exchange compliance.

### Authenticated stdio development transport

The old unsigned wrapper has been removed; stock MCP clients need a Kgaga-aware adapter. The trusted operator selects the child command, configuration and distinct stdio audience. Register a holder-bound agent with appropriate MCP scopes for that audience, mint a passport to a protected file, and sign each individual JSON-RPC request:

```bash
# Use actual protected paths and the registered audience.
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}' |
  kgaga stdio-frame --holder-key /secure/holder.key --passport-file /secure/agent.jwt |
  kgaga wrap --audience stdio-api -- /path/to/trusted-server
```

Each inbound line contains the passport, proof and unpadded base64url of the exact single-line JSON payload separated by TAB characters. Proofs use the existing v1 signature format with synthetic method STDIO, target /mcp, content type application/json and empty MCP header fields. HTTP does not accept the STDIO method. Same-passport sessions only; acquire a new credential and restart the wrapper when needed. A fresh proof is required for every frame; use the same protected replay state as other Kgaga verifiers. The wrapper authenticates and authorizes each frame before forwarding, starts no child before the first allowed frame, validates one matching JSON-RPC result/error for each request, rechecks credential lifecycle before returning a response, and terminates on rejection. Only notifications/initialized is forwarded without waiting for a response. Detected secret patterns block messages when redaction is enabled. Child stderr is discarded. Child pipe I/O is bounded to 30 seconds per admitted frame; local caller input/output can still block. At EOF the wrapper closes/kills and waits for the direct child rather than promising graceful shutdown.

This is not a process sandbox, native MCP-client compatibility, full duplex, response streaming, independent workload attestation or a complete session implementation. Do not run untrusted child commands with access to issuer keys, holder keys, state directories, credentials or sensitive inherited environment variables. The child inherits the operator's OS permissions, working directory and environment. Use external OS isolation and a separately privileged operator for real testing; process descendants are not comprehensively contained. Unsolicited server messages are unsupported and never forwarded as such. No continuous revocation of already dispatched actions is claimed.

## Migration from Pangolin v0.1

This is an early-stage security prototype, not production-ready. The stdio wrapper authenticates each signed frame and enforces MCP policy, but is not an OS sandbox or a complete MCP transport. The current CLI requires v2 passports issued by `kgaga-ca`, with a key thumbprint and explicit audience. Legacy passports are rejected; reissue them before upgrading. The legacy internal verifier is retained for regression coverage, not exposed as a CLI fallback. The HTTP input remains `X-Agent-Passport`. Upstream identity headers are `X-Kgaga-Verified-Agent` / `X-Kgaga-Agent-Owner`; the legacy Pangolin equivalents are also emitted for compatibility. The legacy redaction marker is also preserved. These are not trademark or identity verification claims.

Before switching branches, back up your existing key files and policy securely outside the repository. To preserve an existing identity, copy the matching private and public keys to `kgaga.key` (mode 0600) and `kgaga.pub` and migrate your policy to `kgaga.yaml`. Do not run init over an existing identity. The tracked legacy `pangolin.pub` is historical, not a trusted default for new installations. For a new installation, run `kgaga init` in a dedicated directory. Never commit private keys or bearer tokens.

The Go module now uses `github.com/Leonidas144k/kgaga`; the GitHub repository has been renamed. Planned website: https://kgaga.afrosoft.co.za.

See [the development roadmap](docs/roadmap.md) for planned security work.
