# Everyday Security

**Practical, evidence-based security checks for small-business websites, servers and mail.**
By [Profitell Security Consulting](https://www.profitell.com/) · [profitell.com](https://www.profitell.com/) · [github.com/profitelai/everyday-security](https://github.com/profitelai/everyday-security)

`version 0.1.0` · `Apache-2.0` · `Python 3.9+, standard library only` · `local-first: nothing is sent anywhere except the requests you ask for`

**Tags:** `security-audit` `tls` `http-security-headers` `csp` `hsts` `cookies` `cors` `dns` `small-business` `checklist` `owasp-aligned` `python` `no-dependencies`

## At a glance

<!-- COUNTS:START -->
| Measured from `kb/` | Count |
|---|---:|
| Pillars | **2** |
| Security checks | **16** |
| Run automatically by the site checker | **13** |
| Manual (need server access or a sign-in) | **3** |
| Tags | **31** |
| Public sources cited | **22** |

| Pillar | Checks | Critical | High | Medium | Low | Automated |
|---|---:|---:|---:|---:|---:|---:|
| [`http-headers`](kb/http-headers/) | 10 |  | 4 | 3 | 3 | 9/10 |
| [`tls`](kb/tls/) | 6 |  | 4 | 1 | 1 | 4/6 |
| **Total** | **16** | **** | **8** | **4** | **4** | **13/16** |
<!-- COUNTS:END -->

Full list with tags, tools and severity: [`kb/INDEX.md`](kb/INDEX.md). The counts above are generated from the files in `kb/` by `tools/kb/build_index.py`, so they always match the content.

**Planned pillars, not yet written:** mail authentication (SPF, DKIM, DMARC), web application basics, server hardening, DNS hygiene, backups and recovery. Nothing in this list is counted above.

## What you can check

| You want to check | Pillars | Run it with |
|---|---|---|
| Any website you own or may test, from the outside | `tls`, `http-headers` | `tools/check/everyday_check.py` or the workbench page "Check a website" |
| A server you run (all its domains, mail records, exposed ports, pending updates) | the same, plus host checks | `tools/scanner/security_review.py` (run on the server) |
| One specific item by hand | any check in `kb/` | each check file lists the exact commands |

## How you check

Every check is one file in `kb/<pillar>/<ID>.md` with the same sections: **why it matters · how to test (commands) · pass criteria · fix · risk and rollback**, plus tags, severity, the standards it follows and the sources it cites (`docs/sources.md`).

A check is either **automatic** (the site checker can judge it from outside) or **manual** (it needs server access or a signed-in session; the file tells you how).

Results are `PASS`, `WARN`, `FAIL` or `MANUAL`.

## How to run the tools

**1. Check a website (from the outside, a few ordinary requests):**

```bash
python3 tools/check/everyday_check.py example.com
python3 tools/check/everyday_check.py example.com --json     # machine-readable
```

Only test sites you own or have permission to test. It never probes paths, ports or logins.

**2. Open the local workbench** (browse checks by pillar, tag and severity; run the site checker from a form; inspect provenance):

```bash
python3 tools/workbench/server.py        # then open http://127.0.0.1:5090
```

**3. Review a whole server** (run on the server; discovers every nginx domain, reads DNS and mail records, reports exposed ports):

```bash
sudo SECURITY_REVIEW_EMAIL=you@example.com python3 tools/scanner/security_review.py --no-mail
```

**4. Keep the knowledge base honest:**

```bash
python3 tools/kb/lint.py                  # every check has its fields, sections and known sources
python3 tools/kb/build_index.py           # regenerate kb/INDEX.md and the counts above
python3 tools/kb/similarity.py PATH...    # measure overlap with reference folders before a release
```

## Repository map

| Path | What it is |
|---|---|
| `kb/` | The checks, one file each, grouped by pillar. `kb/INDEX.md` is the generated index. |
| `docs/sources.md` | Source ledger: every public standard the checks cite, with its usage note. |
| `docs/PROVENANCE.md` | Where every part of this repository comes from. |
| `tools/check/` | Site checker (outside view, standard library only). |
| `tools/scanner/` | Server-wide review with history, tickets and optional status email. |
| `tools/workbench/` | Local browser tool: checks, site checker form, provenance and copyright inventory. |
| `tools/kb/` | Lint, index builder, similarity checker. |

## Provenance and independence

Everything here is written by Profitell Security Consulting from public standards (IETF RFCs, W3C and WHATWG specifications, vendor documentation). OWASP cheat sheets are cited, never copied. No third-party knowledge-base content is included. See [`docs/PROVENANCE.md`](docs/PROVENANCE.md).

## License

Apache-2.0, Copyright 2026 Profitell Security Consulting. See `LICENSE` and `NOTICE`.

---

**Profitell Security Consulting** · [https://www.profitell.com/](https://www.profitell.com/) · [https://github.com/profitelai/everyday-security](https://github.com/profitelai/everyday-security)
