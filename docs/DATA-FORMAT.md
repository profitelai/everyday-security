# Data formats: adding data points

New data goes in through one door: `ingest`. Everything lands as **pending**, is validated and de-duplicated, and only a person can make it live with `approve`.

```
CSV / JSON / JSONL  ->  ingest  ->  data/incoming/<file>.json (pending)  ->  approve  ->  data/packs/<file>.json (live)
```

```bash
./everyday.sh ingest --type path_probe --file new_paths.csv --source https://example.org/where-this-came-from --license "CC0"
./everyday.sh approve data/incoming/<file>.json --reviewer "Name"
./everyday.sh list packs      # shows live and pending rules
./everyday.sh validate
```

`--source` is a URL or a ledger ID such as `S-OWASP-A05` (see `docs/sources.md`). `--license` is the licence of the data you are importing, so it can be audited later. A row may carry its own `source` and `license`, which win over the command-line values. In CSV, list fields use `|` as the separator (for example `exposure|secrets`).

## Fields every rule has
| Field | Notes |
|---|---|
| `id` | Optional on ingest (auto-assigned). Prefixes: HDR-R, PRB, VER, TKO, DNR |
| `type` | `http_header`, `path_probe`, `banner_version`, `takeover`, `dns_record` |
| `title` | Short human-readable finding text |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `source`, `license`, `added`, `status`, `author` | Provenance. `status` is `pending`, `approved` or `rejected` |
| `expires` | Optional date (YYYY-MM-DD). Rules past it are skipped, useful for version data |
| `check` | Optional link to a knowledge-base check ID, so the fix text is shown |
| `tags` | Optional list |

## Type-specific fields
| Type | Required | Optional |
|---|---|---|
| `http_header` | `header`, `expect` (`present`, `absent`, `equals`, `regex`, `not_regex`) | `value` (needed for equals/regex/not_regex) |
| `path_probe` | `path` (starts with `/`) | `expect_status` (default 200), `finding_when` (`found`/`missing`), `body_regex`, `not_body_regex` |
| `banner_version` | `header`, `regex` (first group is the version), and `bad_below` or `bad_versions` | `cve` |
| `takeover` | `cname_suffix`, `fingerprint` | |
| `dns_record` | `name` (`{apex}` is replaced by the domain), `rtype`, `expect` (`present`, `absent`, `regex`, `not_regex`) | `value` |

Path probes run only in deep mode, only for sites marked `allow_deep: true`, and a random path is fetched first so catch-all sites do not create false hits.

## New knowledge-base checks
`ingest --type check` creates draft Markdown files in `kb/<pillar>/`. Required columns: `id` (like `ABC-001`), `pillar`, `title`, `severity`, `sources` (ledger IDs, `|`-separated), `tags`, `target`, `method`, `tool`, and the text columns `why`, `test`, `pass`, `fix`, `risk`. Write the text in your own words from public standards. After ingest run `python3 tools/kb/lint.py` and `python3 tools/kb/build_index.py`.

## Sites inventory (`sites/network.json`, kept private)
```json
{"sites": [{"host": "www.example.com", "tags": ["production"], "allow_deep": true, "subdomains": ["mail.example.com"]}]}
```
See `sites/sites.example.json`.
