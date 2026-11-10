# WordPress and CMS

[← Coverage](../README.md)

Updates, plugins, admin exposure, XML-RPC and REST user listing, backups, form spam.

**11 checks** · 0 run automatically · 0 in the server audit · 11 guided checklists · for: WordPress, Drupal, Joomla and similar sites

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [CMS-001](../../kb/wordpress-and-cms/CMS-001.md) | WordPress core, plugins and themes are current, and updates are applied automatically or on a short schedule | high | Guided checklist | OWASP Top 10:2021 A06 |
| [CMS-002](../../kb/wordpress-and-cms/CMS-002.md) | Unused plugins and themes are deleted, and every remaining one is maintained and from a trusted source | medium | Guided checklist | OWASP Top 10:2021 A06 |
| [CMS-003](../../kb/wordpress-and-cms/CMS-003.md) | Few administrator accounts exist, none is named admin, and each has a strong password and a second factor | high | Guided checklist | OWASP Top 10:2021 A07, NIST SP 800-63B |
| [CMS-004](../../kb/wordpress-and-cms/CMS-004.md) | Login attempts to wp-login.php are rate limited so password guessing is slowed or blocked | medium | Guided checklist | OWASP Top 10:2021 A07 |
| [CMS-005](../../kb/wordpress-and-cms/CMS-005.md) | The site does not reveal usernames or version numbers, and XML-RPC is off unless it is needed | medium | Guided checklist | OWASP Top 10:2021 A05 |
| [CMS-006](../../kb/wordpress-and-cms/CMS-006.md) | Dashboard file editing is disabled, and wp-config.php is unreadable from the web with unique secret keys | high | Guided checklist | OWASP Top 10:2021 A05 |
| [CMS-007](../../kb/wordpress-and-cms/CMS-007.md) | File permissions are tight, and PHP files cannot be executed from the uploads folder | high | Guided checklist | OWASP Top 10:2021 A05 |
| [CMS-008](../../kb/wordpress-and-cms/CMS-008.md) | The whole site is served over HTTPS with WordPress configured to match, and security headers are set | medium | Guided checklist | OWASP Top 10:2021 A05, RFC 6797 |
| [CMS-009](../../kb/wordpress-and-cms/CMS-009.md) | Backups cover both files and database, are kept off the server, and a restore has been tested on a staging copy | high | Guided checklist | NIST SP 800-34 |
| [CMS-010](../../kb/wordpress-and-cms/CMS-010.md) | WordPress core and plugin files are checked against official checksums on a schedule, and unexpected files are investigated | high | Guided checklist | OWASP Top 10:2021 A08 |
| [CMS-011](../../kb/wordpress-and-cms/CMS-011.md) | Comments and contact forms resist spam and cannot be abused to send email or upload files | medium | Guided checklist | OWASP Top 10:2021 A04 |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
