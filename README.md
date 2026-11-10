# Everyday Security

**by Profitell Security Consulting** · version 0.1.0 · Apache-2.0

Practical, evidence-based security reviews for small-business websites, servers and mail. Everything runs locally and uses only the Python standard library.

## What is in this repository

| Path | What it does |
|---|---|
| `tools/scanner/security_review.py` | Server-wide review: TLS and certificate expiry, HTTP security headers, mail authentication (SPF/DKIM/DMARC), exposed paths and ports. Writes findings, an HTML report and tickets, diffs against the previous run, and emails only when something new and significant appears. |
| `tools/workbench/` | Local-only browser tool that inventories knowledge bases on a machine, extracts license and copyright wording verbatim, compares a copy with its original file by file, and edits only inside a separate workspace with backups. |
| `kb/` | The knowledge base: one file per check (why, how to test, pass criteria, fix, rollback), each citing public sources. 16 checks so far: 6 TLS, 10 HTTP headers. |
| `tools/kb/` | `lint.py` validates every check and its sources; `similarity.py` measures overlap with any reference folder before release. |
| `docs/sources.md` | The source ledger: every standard the checks cite. |
| `docs/PROVENANCE.md` | Where every part of this repository comes from. |

## Quick start

```bash
# provenance workbench, then open http://127.0.0.1:5090
python3 tools/workbench/server.py

# validate the knowledge base
python3 tools/kb/lint.py

# scanner help
python3 tools/scanner/security_review.py --help
```

Configuration is by environment variables: `SECURITY_REVIEW_EMAIL`, `SECURITY_REVIEW_FROM`, `SECURITY_REVIEW_SERVER_IP`.

## Status

0.1.0 is the first independent release line. The knowledge base is written from public standards (RFCs, W3C and WHATWG specifications, vendor documentation); nothing from any third-party knowledge base is included. Pillars done: TLS, HTTP headers. Next: mail authentication, web-app basics, hosting and server hardening. See `CHANGELOG.md`.

## License

Apache-2.0, Copyright 2026 Profitell Security Consulting. See `LICENSE` and `NOTICE`.
