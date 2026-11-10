"""Where each kind of finding is fixed, and whether Cloudflare can do it.
cloudflare: "yes" = can be done in the Cloudflare dashboard, "partly" = Cloudflare helps but another step is needed, "no" = not a Cloudflare job.
These are hints for the owner, not guarantees: they only apply when the site's DNS and traffic really go through Cloudflare."""

CF = "Cloudflare"
TABLE = {
    "TLS-001": ("Cloudflare and web server", "yes", "Cloudflare: SSL/TLS > Edge Certificates > Minimum TLS Version = 1.2. Also set ssl_protocols TLSv1.2 TLSv1.3 on the origin web server."),
    "TLS-002": ("Certificate and web server", "no", "Renew or reissue the certificate on the origin; with Cloudflare, check the SSL mode is Full (strict)."),
    "TLS-003": ("Web server", "partly", "Cloudflare manages its edge ciphers. Set modern ciphers on the origin web server."),
    "TLS-004": ("Cloudflare", "yes", "SSL/TLS > Edge Certificates > Always Use HTTPS and Automatic HTTPS Rewrites."),
    "TLS-005": ("DNS", "yes", "DNS > Records > add CAA records for the certificate authorities you use. Confirm the certificate still renews afterwards."),
    "TLS-006": ("Web server", "no", "Automate renewal on the origin and monitor expiry."),
    "HDR-001": ("Cloudflare or web server", "yes", "SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS). Start with a short max-age."),
    "HDR-002": ("Cloudflare or application", "partly", "Rules > Transform Rules > Modify Response Header. Start with Content-Security-Policy-Report-Only. Pages that use per-request nonces must set it in the application."),
    "HDR-003": ("Cloudflare or web server", "yes", "Transform Rules > Modify Response Header: X-Frame-Options or CSP frame-ancestors."),
    "HDR-004": ("Cloudflare or web server", "yes", "Transform Rules > Modify Response Header: X-Content-Type-Options: nosniff."),
    "HDR-005": ("Cloudflare or web server", "yes", "Transform Rules > Modify Response Header: Referrer-Policy."),
    "HDR-006": ("Cloudflare or web server", "yes", "Transform Rules > Modify Response Header: Permissions-Policy."),
    "HDR-007": ("Application", "no", "Set Secure, HttpOnly and SameSite where the application creates the cookie."),
    "HDR-008": ("Application or cache rules", "partly", "Application: Cache-Control: private. Cloudflare: Cache Rules must not cache private pages."),
    "HDR-009": ("Web server", "partly", "Remove version banners on the origin (server_tokens off). Cloudflare replaces the Server header on proxied traffic."),
    "HDR-010": ("Application", "no", "Allow only named origins in the application's CORS settings."),
    "MAIL-001": ("DNS", "yes", "DNS > Records: one SPF TXT record, within 10 lookups, ending in -all or ~all."),
    "MAIL-002": ("Mail server and DNS", "partly", "Sign mail with DKIM on the mail server or sending service, then publish the key in DNS."),
    "MAIL-003": ("DNS", "yes", "DNS > Records: _dmarc TXT record with a policy and an rua= address that you read."),
    "MAIL-004": ("DNS", "yes", "Move the _dmarc policy from none to quarantine to reject, guided by the reports."),
    "MAIL-005": ("DNS", "yes", "For domains that send no mail: v=spf1 -all and a reject DMARC."),
    "MAIL-006": ("DNS and a policy file", "partly", "DNS: _mta-sts and _smtp._tls TXT records. The policy file must be served at https://mta-sts.<domain>/.well-known/mta-sts.txt."),
    "MAIL-007": ("Mail server", "no", "Install a certificate for the MX hostname on the mail server."),
    "MAIL-008": ("Mail server", "no", "Restrict relaying in the mail server configuration."),
    "MAIL-009": ("Hosting provider", "no", "Ask the hosting provider to set reverse DNS for the sending IP."),
    "DNS-001": ("Registrar", "no", "Turn on MFA and change alerts at the registrar and DNS provider."),
    "DNS-002": ("Registrar", "no", "Enable the transfer lock at the registrar."),
    "DNS-003": ("Registrar", "no", "Enable auto-renew and monitor the expiry date."),
    "DNS-004": ("DNS provider", "no", "Use at least two independent name servers."),
    "DNS-005": ("DNS and registrar", "partly", "Cloudflare: DNS > Settings > DNSSEC > Enable, then add the DS record it shows at your registrar."),
    "DNS-006": ("DNS provider", "no", "Refuse zone transfers to the public."),
    "DNS-007": ("DNS", "yes", "DNS > Records: delete records that point to services you no longer use."),
    "DNS-008": ("DNS", "yes", "DNS > Records: remove records that point to released IP addresses."),
    "DNS-009": ("DNS", "yes", "DNS > Records: remove private addresses and internal names from public DNS."),
}
PREFIX = [("HDR-R-", ("Cloudflare or web server", "yes", "Transform Rules > Modify Response Header.")), ("DNR-", ("DNS", "yes", "DNS > Records.")),
          ("PRB-0028", ("Web server", "partly", "Publish /.well-known/security.txt on the origin, or serve it with a Cloudflare Worker.")),
          ("PRB-", ("Web server or application", "partly", "Remove the exposed file or path. Until then a Cloudflare WAF custom rule can block it.")),
          ("SRV-", ("Server", "no", "")), ("CTR-", ("Server and Docker", "no", "")), ("APP-", ("Application code", "no", "")), ("CMS-", ("CMS administration", "no", "")),
          ("BAK-", ("People and process", "no", "")), ("IR-", ("People and process", "no", "")), ("PRIV-", ("People and process", "no", "")), ("VEN-", ("People and process", "no", "")), ("CLD-", ("Account settings", "no", ""))]


def where(check_id):
    """(layer, cloudflare, hint) for a check or rule id. Unknown ids get a neutral answer."""
    if check_id in TABLE: return TABLE[check_id]
    for p, v in PREFIX:
        if check_id.startswith(p): return v
    return ("", "no", "")


def cloudflare_summary(results):
    """Counts of open findings (FAIL/WARN) that Cloudflare can fix, partly fix, or not fix."""
    c = {"yes": 0, "partly": 0, "no": 0}
    for r in results:
        if r["status"] in ("FAIL", "WARN"): c[where(r["id"])[1]] += 1
    c["open"] = sum(c.values()); return c
