# Changelog

## 0.2.0 - 2026-11-09
- Data-driven scan engine (`everyday/`): runner groups plus JSON data packs (headers, path probes, banner versions, subdomain takeovers, DNS expectations), 64 seed rules.
- Bulk ingest with validation, de-duplication and a pending-then-approve step; every rule carries source and licence.
- Fleet scans, SQLite history with new/resolved diffs, HTML/Markdown/CSV/JSON reports.
- Workbench "Network scans" page; Claude plugin packaging; architecture and data-format docs; 22 unit tests.

## Unreleased
- Full independent rewrite of the knowledge base: 8 pillars (tls, http-headers, mail-authentication, web-app, server-hardening, dns, backups-and-recovery, privacy-compliance), written from public standards. The site checker now also runs SPF, DMARC, MTA-STS/TLS-RPT, nameserver, DNSSEC and zone-transfer checks and follows redirects before judging headers.
- Added `docs/REVIEW-QUEUE.md` (open verification items) and per-pillar source ledgers in `docs/sources.d/`.
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
