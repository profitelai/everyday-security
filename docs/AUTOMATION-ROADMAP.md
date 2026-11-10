# Automation roadmap: why not every check runs by itself

Status: Alpha 0.2.0. The numbers below are measured from `kb/` (the `automated` field of each check). The tiers and the build order are a plan, not a promise, and the effort notes are estimates.

## Where we are

| How a check runs | Checks | Share |
|---|---:|---:|
| Automatic outside scan (`automated: yes`) | 27 | 21% |
| Server audit, run on the server (`automated: host`) | 9 | 7% |
| Guided checklist, a person answers (`automated: no`) | 94 | 72% |
| **Total** | **130** | |

Some checklist items are already partly covered by data rules (for example 34 rules for exposed secret paths under APP-011, 5 takeover fingerprints under DNS-007, 5 under APP-009). The `automated` field counts a check as automatic only when its full pass criteria are judged by code, so these still show as checklist items.

## Why a check is not automated

There are five different reasons, and each one needs a different fix.

1. **Nothing has been built yet, and it is technically easy.** The check can be judged from public information with no login. This is the largest group we can win quickly.
2. **It can only be seen from inside the server.** Docker settings, process owners, backup jobs and file permissions are invisible from outside. The server audit exists, but it only covers 9 checks so far.
3. **It lives in a file, not on a server.** CI pipelines, lockfiles and update bots are in a repository.
4. **It needs an account.** MFA status, admin counts and OAuth grants in Google, Microsoft or AWS are only visible with a read-only login. Our current promise is that the scanner never logs in anywhere, so this is a policy decision as well as a build task.
5. **It is about people and paperwork.** An incident plan, a vendor contract or a privacy impact assessment exists or it does not. Code cannot judge whether it is any good.

## What can be automated, by tier

| Tier | How | Checks | What it needs | Honest limits |
|---|---|---:|---|---|
| A. Outside scan, new runners | Read-only web, DNS and RDAP requests | 18 | Nothing new | Some stay partial (see below) |
| B. Server audit, more runners | `audit-host` and a new `audit-docker`, local and read-only | 21 | Run on the server | Needs shell access to the server; reports "inconclusive" when run elsewhere |
| C. Repository audit | Read CI files, lockfiles, update-bot config | 3 | Path to a checkout | Judges presence and pinning, not quality |
| D. Account connectors | Read-only APIs of Google Workspace, Microsoft 365, AWS | 7 | Owner-granted read-only token | Breaks the "no logins" promise unless opt-in; must be documented and tested |
| E. Import from other tools | Read SARIF or JSON from Semgrep, OWASP ZAP, Trivy | 7 | The other tool, run by the owner | We import and normalise their findings; we do not replace them |
| F. People and paperwork | Stay a guided checklist, with an **attestation file** | 38 | A named person | A tool cannot prove a plan is good, only that it exists and is current |

Total: 18 + 21 + 3 + 7 + 7 + 38 = 94, the checklist checks today.

### Tier A in detail (outside scan)

| Checks | What the runner does | Notes |
|---|---|---|
| CMS-001, 002, 003, 005, 006, 007, 008 | Fingerprint WordPress (generator tag, `/wp-json/`, `readme.html`), read plugin `readme.txt` versions, list users from `/wp-json/wp/v2/users` and `?author=1`, test `xmlrpc.php`, `wp-config.php` and uploads | Version checks need a "latest version" list. Ship it in the data pack with a date, so the scanner makes no extra outside calls. CMS-002 and CMS-007 stay partial: removed plugins and PHP execution in uploads cannot be fully proven from outside |
| DNS-002, 003 | RDAP lookup of the domain (transfer-lock status, expiry date) | RDAP is a free public standard. Some country registries do not publish lock status, so the answer is then INCONCLUSIVE |
| DNS-007 | Resolve every CNAME found, match against the 5 takeover fingerprints, extend the fingerprints | Needs subdomain discovery from certificate transparency or the inventory file |
| VEN-009 | Parse the page for external scripts and check for `integrity=` (SRI) and a CSP | Fully automatable for the home page and any pages given |
| APP-009 | Detect JavaScript libraries and versions on the page | Judging "vulnerable" needs a vulnerability list. That is a policy change (see decisions) |
| APP-010, 011, 012 | Promote the existing data rules into complete checks with evidence | Mostly done already |
| MAIL-008 | SMTP open-relay test (`RCPT TO` an outside address, no mail sent) | Active probe: only behind an explicit flag, and many hosts block port 25, so often INCONCLUSIVE |
| PRIV-002, 003 | Find a privacy-policy link and a cookie banner in the HTML | Partial: judging whether trackers load **before** consent needs a real browser, which we do not ship |

### Tier B in detail (on the server)

| Checks | What the runner reads |
|---|---|
| CTR-001 to 011 (11 checks, the biggest single win) | `docker inspect` and Compose files: image tags and digests, user, privileged flag and capabilities, socket mounts, secrets in environment, limits and restart policy, networks, volumes, healthchecks and log settings, engine version. One `audit-docker` runner covers the whole pillar |
| SRV-007, 009, 011 | Process owners, a pattern scan for secrets in repositories and dumps, installed-package audit (or import of Trivy output for SRV-011) |
| BAK-001, 003, 006, 007 | Backup timers or cron entries, last success time, encrypted file formats, dump files for databases, count and age of restore points. Whether a restore actually works (BAK-005) stays human |
| CMS-004, 009, 010 | `wp-cli` (`core verify-checksums`, plugin list), `fail2ban` jail for wp-login, backup presence |

### Why 38 stay human

Incident response (10), privacy (8), vendors (6), backups (5), cloud accounts (5) and a few single checks. These ask whether a plan exists, is current and is used. The honest automation is an **attestation file**: a small record with owner, date, a link to the document and an expiry date. The scanner then reports PASS (attested) while it is fresh and WARN when it has expired. That gives a trail and a reminder. It does not prove the plan is good, and the report says so.

## What this buys

| After | Automatic or audited | Guided |
|---|---:|---:|
| Today | 36 (28% of 130) | 94 |
| Tiers A, B, C (no new permissions, no other tools) | about 78 (60%) | about 52 |
| Plus D and E (accounts and imports) | about 92 (71%) | about 38 |

These are upper bounds. Several checks will be partial: the result will be correct for what can be seen and INCONCLUSIVE or MANUAL for the rest.

## Recommended build order

1. **`audit-docker`**: 11 checks from one runner, all local and read-only.
2. **WordPress runner**: the target your clients most often have, 7 checks.
3. **RDAP runner**: DNS-002 and DNS-003, small and clean.
4. **Page-analysis runner**: scripts without SRI, debug pages, privacy-policy link.
5. **Extend the server audit**: SRV-007, 009, 011 and the backup checks.
6. **Repository audit**: CI pins and lockfiles.
7. **Attestation file** for the 38 human checks.
8. **Connectors and imports** last, because they need decisions (below).

Each new runner follows the existing pattern: one function with `@group("name", "CHECK-ID", ...)`, evidence and a confidence level, fixture tests, and a regression test from a recorded real case (as was done for MAIL-007).

## Rule: validate before widening

Every automated check that is wrong costs trust. Before a runner moves a check to `automated: yes`:

- it has fixture tests for pass, fail and inconclusive;
- it has been run against a known-good and a known-bad target we control;
- its status is INCONCLUSIVE, not FAIL, whenever evidence is missing.

This is the same Beta gate as in the [coverage page](coverage/README.md#maturity).

## Decisions needed from the owner

1. **Vulnerability list.** Detecting vulnerable JavaScript libraries or plugins needs a list of known-bad versions. Today we state that we do not match against a vulnerability database. Options: keep that promise and ship only a short hand-written list, or add a clearly labelled, dated feed.
2. **Logins.** Tier D means read-only tokens for Google, Microsoft or AWS. Today the scanner never signs in. Options: keep it that way, or add an opt-in connector with a published list of every API call it makes.
3. **Active probes.** The open-relay test sends an SMTP `RCPT TO`. Options: behind `--i-own-these` only, or not at all.
4. **Test domain.** Known-good and known-bad targets that we control, so accuracy can be measured.
5. **Order.** Confirm the order above, or choose by what clients ask for most.
