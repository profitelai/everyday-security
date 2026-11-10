# DNS hygiene

[← Coverage](../README.md)

Zone transfers, dangling records, private addresses in public DNS, DNSSEC, expiry of names.

**9 checks** · 4 run automatically · 0 in the server audit · 5 guided checklists · for: Any domain

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [DNS-001](../../kb/dns/DNS-001.md) | Registrar and DNS-provider accounts use MFA and send change alerts | high | Guided checklist | - |
| [DNS-002](../../kb/dns/DNS-002.md) | Registrar transfer lock is enabled | high | Guided checklist | RFC 5731 |
| [DNS-003](../../kb/dns/DNS-003.md) | Domain auto-renew is on and expiry is monitored | high | Guided checklist | - |
| [DNS-004](../../kb/dns/DNS-004.md) | At least two nameservers on independent infrastructure answer for the domain | medium | Automatic outside scan | RFC 2182 |
| [DNS-005](../../kb/dns/DNS-005.md) | DNSSEC is enabled where the registrar and DNS host support it, and validates | medium | Automatic outside scan | RFC 4033, RFC 4034, RFC 4035, RFC 9364 |
| [DNS-006](../../kb/dns/DNS-006.md) | Zone transfers (AXFR) are refused to the public | medium | Automatic outside scan | RFC 5936 |
| [DNS-007](../../kb/dns/DNS-007.md) | No CNAME or delegation points at a deprovisioned service (subdomain takeover review) | high | Guided checklist | - |
| [DNS-008](../../kb/dns/DNS-008.md) | No A or AAAA record points at an IP address you have released | medium | Guided checklist | - |
| [DNS-009](../../kb/dns/DNS-009.md) | Public DNS does not expose internal hostnames or private addresses | low | Automatic outside scan | RFC 1918 |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
