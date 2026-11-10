# Review queue

Items the writing passes flagged as unverified or as needing a human decision. Clear each one before a 1.0 release.

| Check | Item | Action |
|---|---|---|
| BAK-006 | `mysqldump --single-transaction` for InnoDB is stated without a citable source (the vendor documentation blocked automated access). | Read the MySQL/MariaDB documentation in a browser and add the source. |
| BAK-005 | The 90-day restore-test interval is a suggestion, not a standard. | Keep as a labelled suggestion or choose a policy. |
| DNS-003 | The 60-day expiry-alert window is a suggestion, not a standard. | Same. |
| MAIL-002, MAIL-001, MAIL-009 | Commands using `swaks` and `checkdmarc` were not executed during drafting. | Run each once and confirm the output matches the text. |
| SRV-005, SRV-003 | `needrestart` flags and MySQL default bind behaviour were left out as unverified. | Add after verification. |
| PRIV-001 to PRIV-010 | Law 25 in-force dates, retention periods from other laws, language-of-publication rules, GDPR applicability and DPIA were left for counsel. | Lawyer review. |
| All | Written by AI-assisted drafting from public sources; not yet reviewed by a named human security professional. | Human technical review of every check; record reviewer and date in the front matter. |


## Added 2026-11-09: five new pillars (incident response, cloud and SaaS, WordPress and CMS, containers, vendor and supply chain)
All 51 checks are `status: draft`. Each writer was asked to list claims it was unsure about; a human technical reviewer should confirm these before the checks are called final:
- **Commands never run.** CLI examples (docker inspect formats, Trivy and Docker Scout flags, `gh api` org MFA calls, AWS and gcloud output fields, `npm audit signatures`, `npm sbom`, `pip-compile --generate-hashes`, `wp core download --skip-content`, `wp db export` with mysqldump flags, `postsuper -h ALL`, `lsof -nP +L1`, CISA KEV `jq` filters) come from the writers' knowledge of the tools and were not executed.
- **Numbers that are our suggestion, not a standard:** log retention of 90 days searchable and 12 months archived (IR-006); post-incident review within two weeks (IR-008); API key rotation yearly, OAuth app review every six months (CLD); plugin freshness of about 12 months, update windows of 7 and 30 days (CMS-001/002); container limit sizing, weekly scans, monthly rebuilds, one-week critical-patch window (CTR).
- **Legal pointers (counsel to review):** PIPEDA and Quebec notification timing wording in IR-007; Law 25 cross-border assessment coverage in VEN-003 and PRIV-009.
- **Partly read sources:** CISA IRP Basics (detail in a linked PDF), CISA logging guidance (no retention figure), AICPA SOC page (app shell), Google offboarding pages (summaries), Cloudflare roles page (skimmed). NIST SP 800-61 Rev. 2 is kept as a withdrawn historical reference.
- **ISO/IEC 27035 and 27001** are named under `standards` but not cited as sources, because iso.org returns 403 to automated fetches.
- **Behaviour claims to verify:** Compose honours `deploy.resources.limits` outside Swarm; Docker live-restore and major-version upgrades; WordPress REST users endpoint and XML-RPC users (Jetpack, mobile apps); GitHub default `GITHUB_TOKEN` permissions depend on org settings.
- **Severities** of all new checks are judgement calls.
