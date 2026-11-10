# Email authentication and transport

[← Coverage](../README.md)

SPF, DKIM, DMARC, MTA-STS, MX encryption (STARTTLS), reverse DNS.

**10 checks** · 8 run automatically · 0 in the server audit · 2 guided checklists · for: Any domain that sends or receives mail

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [MAIL-001](../../kb/mail-authentication/MAIL-001.md) | SPF is published once, stays within 10 DNS lookups and ends in -all or ~all | high | Automatic outside scan | RFC 7208 |
| [MAIL-002](../../kb/mail-authentication/MAIL-002.md) | Outgoing mail is DKIM-signed with a 2048-bit key published in DNS | high | Automatic outside scan | RFC 6376, RFC 8301 |
| [MAIL-003](../../kb/mail-authentication/MAIL-003.md) | A single DMARC record exists with a valid policy and an aggregate-report address | high | Automatic outside scan | RFC 7489 |
| [MAIL-004](../../kb/mail-authentication/MAIL-004.md) | DMARC policy is moved from none to quarantine to reject, guided by reports | high | Automatic outside scan | RFC 7489 |
| [MAIL-005](../../kb/mail-authentication/MAIL-005.md) | Domains that never send or receive mail publish a deny-all SPF, a reject DMARC and a null MX | medium | Automatic outside scan | RFC 7208, RFC 7489, RFC 7505 |
| [MAIL-006](../../kb/mail-authentication/MAIL-006.md) | MTA-STS is enforced and TLS-RPT reporting is enabled for incoming mail | medium | Automatic outside scan | RFC 8461, RFC 8460 |
| [MAIL-007](../../kb/mail-authentication/MAIL-007.md) | Every MX host offers STARTTLS with a valid certificate and TLS 1.2 or newer | medium | Automatic outside scan | RFC 3207, RFC 8461 |
| [MAIL-008](../../kb/mail-authentication/MAIL-008.md) | The mail server is not an open relay | critical | Guided checklist | RFC 5321 |
| [MAIL-009](../../kb/mail-authentication/MAIL-009.md) | Each outgoing mail IP has a reverse DNS name that resolves back to the same IP | medium | Automatic outside scan | RFC 1912, RFC 5321 |
| [MAIL-010](../../kb/mail-authentication/MAIL-010.md) | Mailbox accounts use multi-factor authentication and strong, unique passwords | high | Guided checklist | NIST SP 800-63B |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
