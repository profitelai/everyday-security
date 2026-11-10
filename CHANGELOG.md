# Changelog

## Unreleased
- New result status `INCONCLUSIVE` and recorded `evidence` plus `confidence` on findings (stored in the history database, shown in HTML, Markdown and CSV reports; older databases upgrade in place).
- MAIL-007 rebuilt: the mail certificate is judged on three separate questions (chain, name, expiry). A name mismatch is a warning, and a failure only when MTA-STS enforce or DANE is published. A blocked port 25 is `INCONCLUSIVE`. The facilinvoice.ca case is a permanent regression test.
- `tools/scanner/security_review.py`: every check cites a public standard (SPEC table); fixed dangling-CNAME, DKIM-selector and multi-cookie handling; SPF, DMARC and HSTS gaps are no longer rated as high-impact; firewall findings are labelled inferred with low confidence and capped in severity.
- Added `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`; 34 more tests (66 total); closed files properly in `ingest.py`.
- README: Alpha status banner and Disclaimer; the scan description now lists exactly what a scan sends (it wrongly said it never probes ports).
- Check front matter: `reviewed` renamed to `drafted` (no human review has happened); "not legal advice" note added to the 12 checks that cite statutes or regulators; PROVENANCE states plainly that the content was drafted by an AI assistant.

## 0.2.0 - 2026-11-09
- Data-driven scan engine (`everyday/`): runner groups plus JSON data packs (headers, path probes, banner versions, subdomain takeovers, DNS expectations), 64 seed rules.
- Bulk ingest with validation, de-duplication and a pending-then-approve step; every rule carries source and licence.
- Fleet scans, SQLite history with new/resolved diffs, HTML/Markdown/CSV/JSON reports.
- 8 more checks now run automatically (27 of 78): DKIM key size, DMARC policy progress, deny-all for non-mail domains, MX STARTTLS, MX reverse DNS, private addresses in public DNS, cache headers, TLS cipher posture.
- Five new draft pillars (51 checks, 130 total in 13 pillars): incident response, cloud and SaaS accounts, WordPress and CMS, containers, vendor and supply chain; 156 more cited sources (309 total).
- `audit-host`: read-only server audit covering 9 checks (SSH, firewall, listening ports, Docker ports, updates, fail2ban, clock, web-root permissions, cert renewal).
- Controlled tag vocabulary (`data/tags.json`, 68 tags, enforced by lint) replaces 196 ad-hoc tags.
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
