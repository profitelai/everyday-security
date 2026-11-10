# HTTP security headers

[← Coverage](../README.md)

HSTS, CSP, frame protection, cookies, CORS, caching of private pages, version disclosure.

**10 checks** · 10 run automatically · 0 in the server audit · 0 guided checklists · for: Any website or web app

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [HDR-001](../../kb/http-headers/HDR-001.md) | Strict-Transport-Security is sent on every HTTPS response | high | Automatic outside scan | RFC 6797 |
| [HDR-002](../../kb/http-headers/HDR-002.md) | A Content-Security-Policy limits where scripts and other resources load from | high | Automatic outside scan | CSP Level 3 |
| [HDR-003](../../kb/http-headers/HDR-003.md) | Pages cannot be framed by other sites (clickjacking protection) | medium | Automatic outside scan | CSP Level 3, RFC 7034 |
| [HDR-004](../../kb/http-headers/HDR-004.md) | X-Content-Type-Options: nosniff is sent | medium | Automatic outside scan | Fetch Standard |
| [HDR-005](../../kb/http-headers/HDR-005.md) | Referrer-Policy limits what URLs leak to other sites | low | Automatic outside scan | Referrer Policy |
| [HDR-006](../../kb/http-headers/HDR-006.md) | Permissions-Policy switches off browser features the site does not use | low | Automatic outside scan | Permissions Policy |
| [HDR-007](../../kb/http-headers/HDR-007.md) | Session and authentication cookies carry Secure, HttpOnly and SameSite | high | Automatic outside scan | RFC 6265bis |
| [HDR-008](../../kb/http-headers/HDR-008.md) | Responses with private data are not cached by browsers or shared caches | medium | Automatic outside scan | RFC 9111 |
| [HDR-009](../../kb/http-headers/HDR-009.md) | Server and framework version banners are not exposed | low | Automatic outside scan | RFC 9110 |
| [HDR-010](../../kb/http-headers/HDR-010.md) | CORS allows only named origins and never combines a wildcard with credentials | high | Automatic outside scan | Fetch Standard |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
