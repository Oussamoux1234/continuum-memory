# Security policy

This repository is an experimental plaintext prototype, not a production security release.
Do not store sensitive data in it. Known limitations include the same-UID terminal approval
boundary, unencrypted SQLite/FTS/WAL storage, shared FTS projection, no backup revocation,
same-UID filesystem replacement races, and no independently validated Linux user-presence
backend. Owner/type/mode/link checks reduce accidental exposure and cross-account attacks;
they are not a sandbox against programs already running as the user.

Please report vulnerabilities through a private GitHub security advisory at
`github.com/Oussamoux1234/continuum-memory/security/advisories/new`. Do not open a public
issue containing exploit details, credentials, memory bodies, capability files, or vaults.

Useful reports identify the affected commit/version, trust boundary, synthetic reproduction,
impact, and whether the issue crosses project/disclosure/approval/deletion invariants. No
response-time or bounty promise exists until the project publishes a formal policy.
