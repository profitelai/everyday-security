# TLS and certificates

[← Coverage](../README.md)

HTTPS certificates, expiry, protocol versions, ciphers, redirects from HTTP.

**6 checks** · 5 run automatically · 1 in the server audit · 0 guided checklists · for: Any website

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [TLS-001](../../kb/tls/TLS-001.md) | Only TLS 1.2 and TLS 1.3 are accepted | high | Automatic outside scan | RFC 8996, RFC 8446 |
| [TLS-002](../../kb/tls/TLS-002.md) | Certificate is valid, complete, matches the name, and is not close to expiry | high | Automatic outside scan | RFC 5280, RFC 6125 |
| [TLS-003](../../kb/tls/TLS-003.md) | Cipher suites are modern and give forward secrecy | medium | Automatic outside scan | RFC 9325, RFC 8446 |
| [TLS-004](../../kb/tls/TLS-004.md) | Plain HTTP redirects to HTTPS, with no mixed content | high | Automatic outside scan | RFC 9110 |
| [TLS-005](../../kb/tls/TLS-005.md) | DNS CAA records restrict which authorities may issue certificates | low | Automatic outside scan | RFC 8659 |
| [TLS-006](../../kb/tls/TLS-006.md) | Certificate renewal is automatic and monitored | high | Server audit | RFC 8555 |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
