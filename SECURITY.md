# Security policy

## Supported status

Kgaga is an experimental single-host identity and gateway prototype. No version is designated production-ready or guaranteed to receive security updates. Do not expose this prototype to untrusted networks or rely on it as the sole boundary protecting real data, payments or production systems. The restricted stdio wrapper verifies signed frames but is not an OS sandbox or a production security boundary.

## Reporting

Use the repository's GitHub Security tab to check whether private vulnerability reporting is available. If enabled, report privately there. If it is not available, request a private reporting channel from the maintainer without posting vulnerability details, secrets, or customer data in public issues. A dedicated security mailbox, response SLA and disclosure process have not yet been established. Do not claim they exist.

Include the affected commit, platform, a minimal reproduction using synthetic data, expected versus observed behavior, and potential impact. Never include live private keys, tokens or customer records. Test only on systems you own or have authorization to assess.

## Handling sensitive material

Keep private issuer and holder keys and all state directories outside version control. Protect parent directories and private files with OS permissions. Do not restore stale trust or revocation state or recreate lost stores as empty. Isolate upstream services so only the trusted gateway can reach them. Use authenticated encrypted transport; loopback defaults are not a general deployment control. The verify command can output embedded parent credentials; treat its output as sensitive.

See [threat model](docs/THREAT_MODEL.md) and [release checklist](docs/RELEASE_CHECKLIST.md).
