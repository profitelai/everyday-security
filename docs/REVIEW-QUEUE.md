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
