# Architecture

Everyday Security separates **what to know** from **what to run** from **what to remember**, so each can grow independently.

| Layer | Where | Grows by |
|---|---|---|
| Knowledge base | `kb/<pillar>/<ID>.md` | New checks (fix, test, rollback, sources) |
| Source ledger | `docs/sources*.md` | New public sources (`S-...` IDs) |
| Runners | `everyday/runners/*.py` | Code that tests something a rule cannot express (TLS handshakes, SPF lookups) |
| Data packs | `data/packs/*.json` | Thousands of rules: headers, paths, versions, takeovers, DNS |
| Pending data | `data/incoming/*.json` | Bulk ingest awaiting a reviewer |
| Engine | `everyday/engine.py`, `rules.py`, `context.py` | Rarely; it is generic |
| History | `reports/history.db` (SQLite) | Every run, for new/resolved diffs |
| Reports | `reports/runs/<stamp>/` | HTML, Markdown, CSV and JSON per run |
| Interfaces | `everyday.sh` CLI, workbench (localhost), Claude plugin | |

## One site scan
1. `Context` fetches the main page once (following up to three HTTPS redirects) and caches DNS answers.
2. Runner groups (code) produce results for the checks they cover (`@group(name, *ids)`).
3. `run_rules` evaluates every approved data rule against the same context. Path probes run only in deep mode.
4. A runner returns `(check id, status, detail)` or `(check id, status, detail, {"evidence": ..., "confidence": "high|medium|low"})`; evidence is stored with the result and shown in reports. Use `INCONCLUSIVE` when there is not enough evidence to judge (for example a blocked port).
5. Results are scored (`FAIL` costs 2x severity weight, `WARN` 1x; MANUAL, INCONCLUSIVE, PASS and INFO cost nothing) and graded A to F. The grade is a comparison aid, not a certification.
5. The run is stored; the report lists findings that are new or resolved since the previous run of the same site.

## Server audit
`./everyday.sh audit-host` (run on the server, ideally as root) reads local state only (no changes, no network calls) and judges the server-hardening checks that cannot be seen from outside: SSH policy, firewall default, listening ports, Docker published ports, automatic updates, fail2ban, clock sync, web-root permissions and certificate renewal. The result is stored like a site scan, so reports, history and diffs work the same. Checks it covers are marked `automated: host`. Parsers are pure functions in `everyday/hostaudit.py` with fixture tests; Debian/Ubuntu-specific checks report MANUAL on other systems.

## Fleet scan
`scan --sites sites/network.json` runs one site per worker thread, with tags to select subsets. Deep mode needs both `allow_deep: true` for the site and `--deep --i-own-these` on the command line.

## Adding capacity
- More of an existing kind (more paths, headers, versions, takeover fingerprints, DNS expectations): ingest, review, approve. No code change.
- A new kind of test: add a runner group in `everyday/runners/` and list its check IDs; mark the check `automated: yes`; add a unit test.
- A new rule type: add it to `registry.RULE_TYPES` and `validate_rule`, an evaluator in `rules.py`, and a key in `ingest.KEYS`.

## Safety rules built in
- No scanning of private addresses from the workbench. Probing sensitive paths needs per-site opt-in.
- Every rule carries a source and a licence; rules can expire.
- Nothing becomes live without a named reviewer.
- Own words only: knowledge-base text is written from public standards and cited, never pasted.
