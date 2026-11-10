# Changelog

## Unreleased
- Knowledge base started: TLS (TLS-001..006) and HTTP headers (HDR-001..010), all written from public standards; source ledger in `docs/sources.md`.
- Added `tools/kb/lint.py`, `tools/kb/similarity.py` and `tools/kb/build_index.py` (generates `kb/INDEX.md` and the README counts).
- Every check now carries tags, target, method, tool and an automation flag.
- Added `tools/check/everyday_check.py`, a standalone site checker for the 13 automatable checks, and a "Check a website" page in the workbench.
- README reorganized: counts per pillar, what and how to check, how to run each tool; backlinks to https://www.profitell.com/.

## 0.1.0 (2026-11-09)
- New repository, new name: Everyday Security by Profitell Security Consulting.
- Added the server-wide security review scanner (our own code), generalized: no hard-coded server addresses or mailboxes, configured by environment variables.
- Added the local provenance workbench (our own code).
- Added Apache-2.0 license, NOTICE and provenance statement.
