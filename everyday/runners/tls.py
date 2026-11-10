import datetime as dt, socket, ssl
from . import group
from ..context import tls_try, fetch

@group("tls", "TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-005", "TLS-006")
def tls(ctx):
    host, out = ctx.host, []
    v12, v13 = tls_try(host, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2), tls_try(host, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    old = [n for n, v in (("1.0", ssl.TLSVersion.TLSv1), ("1.1", ssl.TLSVersion.TLSv1_1)) if tls_try(host, v, v) not in ("refused", "unavailable")]
    untestable = tls_try(host, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1) == "unavailable"
    if old: out.append(("TLS-001", "FAIL", "accepts TLS " + " and ".join(old)))
    elif v12 in ("refused", "unavailable") and v13 in ("refused", "unavailable"): out.append(("TLS-001", "FAIL", "no modern TLS handshake succeeded"))
    elif untestable: out.append(("TLS-001", "MANUAL", f"1.2: {v12}, 1.3: {v13}; this Python/OpenSSL cannot offer TLS 1.0/1.1, so test those with nmap or an old openssl"))
    else: out.append(("TLS-001", "PASS" if v13 != "refused" else "WARN", f"TLS 1.2: {'yes' if v12=='TLSv1.2' else 'no'}, TLS 1.3: {'yes' if v13=='TLSv1.3' else 'no'}; 1.0/1.1 refused"))
    cipher = None
    try:
        c = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=ctx.timeout) as s, c.wrap_socket(s, server_hostname=host) as t: cert = t.getpeercert(); cipher = t.cipher()
        left = (dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z") - dt.datetime.utcnow()).days
        names = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        out.append(("TLS-002", "FAIL" if left < 7 else "WARN" if left < 30 else "PASS", f"chain and name verified; {left} days left; issuer {dict(x[0] for x in cert['issuer']).get('organizationName','?')}; names: {', '.join(names[:4])}"))
    except ssl.SSLCertVerificationError as e: out.append(("TLS-002", "FAIL", "certificate does not verify: " + (e.verify_message or str(e))))
    except OSError as e: out.append(("TLS-002", "FAIL", "cannot open an HTTPS connection: " + str(e)))
    out.append(("TLS-003", "MANUAL", (f"negotiated {cipher[0]}; " if cipher else "") + "full suite list needs: nmap --script ssl-enum-ciphers"))
    try:
        r = fetch(host, 80, timeout=ctx.timeout); st, loc = r["status"], r["headers"].get("location", "")
        if st in (301, 308) and loc.lower().startswith("https://"): out.append(("TLS-004", "PASS", f"HTTP {st} to {loc}"))
        elif st in (302, 303, 307) and loc.lower().startswith("https://"): out.append(("TLS-004", "WARN", f"redirects with {st} (temporary), prefer 301/308: {loc}"))
        else: out.append(("TLS-004", "FAIL", f"http:// answered {st}" + (f" to {loc}" if loc else "") + " instead of redirecting to https"))
    except OSError as e: out.append(("TLS-004", "WARN", "port 80 not reachable (" + str(e) + "); acceptable only if intentionally closed"))
    if ctx.has_dig:
        caa = ctx.dig("CAA", host) or ctx.dig("CAA", ctx.apex)
        out.append(("TLS-005", "PASS" if caa else "WARN", "; ".join(caa) if caa else "no CAA record found (low severity)"))
    else: out.append(("TLS-005", "MANUAL", "dig is not installed; run: dig +short CAA " + host))
    out.append(("TLS-006", "MANUAL", "renewal automation lives on the server; see kb/tls/TLS-006.md"))
    return out
