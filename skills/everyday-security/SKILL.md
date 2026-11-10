---
name: everyday-security
description: Scan websites and whole networks for security problems with the Everyday Security engine (Profitell Security Consulting), read the reports, look up how to fix a check, and add new data points (rules or checks) through the pending-then-approve pipeline. Use when the user asks to scan a site or network, check TLS, headers, DNS, mail authentication, exposed files, or to add or review security data.
---

# Everyday Security

Run everything from the repository root (the folder that holds `everyday.sh`).

## Scan
- One or more sites: `./everyday.sh scan example.com other.com`
- A whole network from an inventory file: `./everyday.sh scan --sites sites/network.json` (tags: `--tag production`; subsets: `--pillars tls,dns` or `--ids TLS-001,HDR-001`)
- Deep scan (probes about 44 well-known sensitive paths; only for sites the user owns, per-site `allow_deep: true`): add `--deep --i-own-these`
- Reports land in `reports/runs/<stamp>/` as `report.html`, `report.md`, `findings.csv`, `results.json`; history is in `reports/history.db` and each report shows what is new or resolved since the previous run.
- Only test sites the user owns or may test. Never run a deep scan against anyone else's site.

- On a server itself (read-only, ideally as root): `./everyday.sh audit-host`

## Read results
`FAIL`/`WARN` are findings, `MANUAL` means it cannot be judged from outside, `INFO` is a note. Every finding names its check ID; the fix, the test commands and the rollback are in `kb/<pillar>/<ID>.md`. Scores are a comparison aid, not a certification.

## Add data points (thousands are expected)
1. Put them in a CSV, JSON or JSONL file. Rule types: `http_header`, `path_probe`, `banner_version`, `takeover`, `dns_record`; or `check` for new knowledge-base checks. Column names are the field names in `docs/DATA-FORMAT.md`; list fields use `|`.
2. `./everyday.sh ingest --type path_probe --file new.csv --source <URL or S-ID> --license "<license of the data>"` creates a PENDING file in `data/incoming/` and reports duplicates and invalid rows. Every record needs a real source; never invent one.
3. A human reviews, then `./everyday.sh approve data/incoming/<file>.json --reviewer "<name>"` makes it live. Do not approve on the user's behalf unless they said to.
4. `./everyday.sh validate` and `python3 -m unittest discover -s tests` must pass before finishing.

## Rules
- Knowledge-base text is written in our own words from public standards; never copy another project's text.
- Do not change the license, make the repository public, or push to GitHub unless the user has said so.
