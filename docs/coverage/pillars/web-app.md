# Web application safeguards

[← Coverage](../README.md)

Login, sessions, uploads, injection, access control and error handling (review-based).

**12 checks** · 0 run automatically · 0 in the server audit · 12 guided checklists · for: Sites and apps you build or run

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [APP-001](../../kb/web-app/APP-001.md) | Private pages and records are checked against the logged-in user on the server | high | Guided checklist | OWASP Top 10:2021 A01 |
| [APP-002](../../kb/web-app/APP-002.md) | Database queries use parameterized statements, never string-built SQL | critical | Guided checklist | OWASP Top 10:2021 A03 |
| [APP-003](../../kb/web-app/APP-003.md) | Anything a visitor can supply is encoded for its output context | high | Guided checklist | OWASP Top 10:2021 A03 |
| [APP-004](../../kb/web-app/APP-004.md) | State-changing requests are protected against cross-site request forgery | medium | Guided checklist | OWASP Top 10:2021 A01 |
| [APP-005](../../kb/web-app/APP-005.md) | Login is rate-limited, admin accounts use MFA, and password reset is safe | high | Guided checklist | OWASP Top 10:2021 A07, NIST SP 800-63B |
| [APP-006](../../kb/web-app/APP-006.md) | Sessions are renewed at login, expire, and are ended at logout | medium | Guided checklist | OWASP Top 10:2021 A07 |
| [APP-007](../../kb/web-app/APP-007.md) | Passwords are stored with a slow, salted hash such as Argon2id | high | Guided checklist | OWASP Top 10:2021 A02, NIST SP 800-63B |
| [APP-008](../../kb/web-app/APP-008.md) | File uploads are limited by type and size and cannot be run as code | high | Guided checklist | OWASP Top 10:2021 A04 |
| [APP-009](../../kb/web-app/APP-009.md) | Libraries, plugins and frameworks are scanned for known vulnerabilities and kept updated | high | Guided checklist | OWASP Top 10:2021 A06 |
| [APP-010](../../kb/web-app/APP-010.md) | Debug mode is off and error pages do not reveal stack traces or file paths | medium | Guided checklist | OWASP Top 10:2021 A05 |
| [APP-011](../../kb/web-app/APP-011.md) | Secrets, backups, repository folders and phpinfo are not reachable over the web, and directory listing is off | high | Guided checklist | OWASP Top 10:2021 A05 |
| [APP-012](../../kb/web-app/APP-012.md) | Admin and database-management panels are not open to the whole internet | medium | Guided checklist | OWASP Top 10:2021 A05, OWASP Top 10:2021 A01 |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
