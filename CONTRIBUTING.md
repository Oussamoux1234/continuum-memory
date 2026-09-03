# Contributing

Continuum Memory is an experimental prototype. Before proposing code, read
`docs/PRODUCT_CONSTITUTION.md` and the relevant ADRs. Changes may extend projections or
adapters, but may not weaken canonical provenance, temporal history, scoped disclosure,
approval separation, deletion semantics, or the rule that memory is never authorization.

Run the complete local gate before opening a pull request:

```bash
python3 scripts/verify.py
```

Use synthetic data in tests and issues. Never submit credentials, private memory bodies,
real agent profiles, transcript databases, or user vaults. New runtime dependencies need a
documented license, maintenance, vulnerability, and offline-runtime review. Native profile
tests must use temporary homes unless a maintainer explicitly runs a manual opt-in check.

Commits should stay scoped to one architectural outcome and update tests plus docs together.
Roadmap work belongs to the milestone categories in `docs/MILESTONES.md`.
