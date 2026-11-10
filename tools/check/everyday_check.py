#!/usr/bin/env python3
"""Everyday Security site checker: runs the automatable checks from kb/ against one website, from the outside.

    python3 tools/check/everyday_check.py example.com
    python3 tools/check/everyday_check.py https://example.com --json

Only a few ordinary requests are made (one HTTPS page, one HTTP page, one TLS handshake per protocol, one DNS CAA
lookup, two requests carrying a test Origin header). It never probes paths, ports or logins.
Run it only against sites you own or are allowed to test.

Result per check: PASS, FAIL, WARN, MANUAL (cannot be judged from outside; the check file says how to test it).
Exit code 1 if any FAIL.  Standard library only.   Profitell Security Consulting · https://www.profitell.com/
"""
import argparse, datetime as dt, http.client, json, re, shutil, socket, ssl, subprocess, sys
from urllib.parse import urlparse

UA = "Mozilla/5.0 (compatible; EverydaySecurity/0.1; +https://github.com/profitelai/everyday-security)"
HOME = "https://www.profitell.com/"; REPO = "https://github.com/profitelai/everyday-security"

def conn(host, port, ctx=None, timeout=10):
    return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx) if port == 443 else http.client.HTTPConnection(host, port, timeout=timeout)

def req(host, port, path="/", headers=None):
    c = conn(host, port); h = {"User-Agent": UA, "Accept": "*/*"}; h.update(headers or {})
    try:
        c.request("GET", path, headers=h); r = c.getresponse(); r.read(2048)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.msg.get_all("Set-Cookie") or []
    finally: c.close()

def tls_try(host, lo, hi):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try: ctx.minimum_version, ctx.maximum_version = lo, hi
    except (ValueError, ssl.SSLError): return "unavailable"
    try:
        with socket.create_connection((host, 443), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t: return t.version()
    except ssl.SSLError as e:
        return "unavailable" if "UNSUPPORTED_PROTOCOL" in str(e).upper() and "NO_PROTOCOLS" in str(e).upper() else "refused"
    except OSError: return "refused"

R = []
def res(i, status, detail): R.append({"id": i, "status": status, "detail": detail})

def run(host):
    # ---- TLS ----
    v12, v13 = tls_try(host, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2), tls_try(host, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    old = [n for n, v in (("1.0", ssl.TLSVersion.TLSv1), ("1.1", ssl.TLSVersion.TLSv1_1)) if tls_try(host, v, v) not in ("refused", "unavailable")]
    untestable = tls_try(host, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1) == "unavailable"
    if old: res("TLS-001", "FAIL", "accepts TLS " + " and ".join(old))
    elif v12 in ("refused", "unavailable") and v13 in ("refused", "unavailable"): res("TLS-001", "FAIL", "no modern TLS handshake succeeded")
    elif untestable: res("TLS-001", "MANUAL", f"1.2: {v12}, 1.3: {v13}; this Python/OpenSSL cannot offer TLS 1.0/1.1, so test those with nmap or an old openssl")
    else: res("TLS-001", "PASS" if v13 != "refused" else "WARN", f"TLS 1.2: {'yes' if v12=='TLSv1.2' else 'no'}, TLS 1.3: {'yes' if v13=='TLSv1.3' else 'no'}; 1.0/1.1 refused")
    cipher = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert(); cipher = t.cipher()
        left = (dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z") - dt.datetime.utcnow()).days
        names = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        res("TLS-002", "FAIL" if left < 7 else "WARN" if left < 30 else "PASS", f"chain and name verified; {left} days left; issuer {dict(x[0] for x in cert['issuer']).get('organizationName','?')}; names: {', '.join(names[:4])}")
    except ssl.SSLCertVerificationError as e: res("TLS-002", "FAIL", "certificate does not verify: " + (e.verify_message or str(e)))
    except OSError as e: res("TLS-002", "FAIL", "cannot open an HTTPS connection: " + str(e))
    res("TLS-003", "MANUAL", (f"negotiated {cipher[0]} ({cipher[1]}); " if cipher else "") + "full suite list needs: nmap --script ssl-enum-ciphers")
    try:
        st, h, _ = req(host, 80); loc = h.get("location", "")
        if st in (301, 308) and loc.lower().startswith("https://"): res("TLS-004", "PASS", f"HTTP {st} to {loc}")
        elif st in (302, 303, 307) and loc.lower().startswith("https://"): res("TLS-004", "WARN", f"redirects with {st} (temporary), prefer 301/308: {loc}")
        else: res("TLS-004", "FAIL", f"http:// answered {st}" + (f" to {loc}" if loc else "") + " instead of redirecting to https")
    except OSError as e: res("TLS-004", "WARN", "port 80 not reachable (" + str(e) + "); acceptable only if intentionally closed")
    if shutil.which("dig"):
        out = subprocess.run(["dig", "+short", "CAA", host.split(":")[0]], capture_output=True, text=True, timeout=15).stdout.strip()
        if not out:
            parts = host.split("."); apex = ".".join(parts[-2:]); out = subprocess.run(["dig", "+short", "CAA", apex], capture_output=True, text=True, timeout=15).stdout.strip() if len(parts) > 2 else ""
        res("TLS-005", "PASS" if out else "WARN", out.replace("\n", "; ") if out else "no CAA record found (low severity)")
    else: res("TLS-005", "MANUAL", "dig is not installed; run: dig +short CAA " + host)
    res("TLS-006", "MANUAL", "renewal automation lives on the server; see kb/tls/TLS-006.md")
    # ---- headers ----
    try: st, h, cookies = req(host, 443)
    except OSError as e:
        for i in ("HDR-%03d" % n for n in range(1, 11)): res(i, "MANUAL", "HTTPS page could not be fetched: " + str(e))
        return
    hs = h.get("strict-transport-security", ""); m = re.search(r"max-age=(\d+)", hs, re.I)
    res("HDR-001", "PASS" if m and int(m.group(1)) >= 15552000 else "WARN" if m else "FAIL", hs or "header missing")
    csp = h.get("content-security-policy", "")
    if not csp: res("HDR-002", "FAIL", "no Content-Security-Policy header")
    else:
        sc = re.search(r"(?:^|;)\s*script-src\s+([^;]*)", csp) or re.search(r"(?:^|;)\s*default-src\s+([^;]*)", csp); sv = sc.group(1) if sc else ""
        bad = [x for x in ("'unsafe-inline'", "'unsafe-eval'") if x in sv] + (["wildcard"] if re.search(r"(^|\s)\*(\s|$)", sv) else [])
        if "'nonce-" in sv or "'strict-dynamic'" in sv: bad = [b for b in bad if b != "'unsafe-inline'"]
        res("HDR-002", "WARN" if bad or not sc else "PASS", ("weak script policy: " + ", ".join(bad)) if bad else ("no script-src or default-src" if not sc else "script policy has no unsafe-inline/eval/wildcard"))
    fa = "frame-ancestors" in csp; xfo = h.get("x-frame-options", "").upper()
    res("HDR-003", "PASS" if fa or xfo in ("DENY", "SAMEORIGIN") else "FAIL", f"frame-ancestors: {'yes' if fa else 'no'}; X-Frame-Options: {xfo or 'none'}")
    res("HDR-004", "PASS" if h.get("x-content-type-options", "").lower() == "nosniff" else "FAIL", h.get("x-content-type-options", "header missing"))
    rp = h.get("referrer-policy", "").lower()
    res("HDR-005", "PASS" if rp.split(",")[-1].strip() in ("strict-origin-when-cross-origin", "same-origin", "no-referrer", "strict-origin", "origin-when-cross-origin") else "WARN", rp or "header missing (browser default applies)")
    res("HDR-006", "PASS" if h.get("permissions-policy") else "WARN", (h.get("permissions-policy") or "header missing")[:120])
    if not cookies: res("HDR-007", "PASS", "no cookies set on the home page (sign-in pages must be checked by hand)")
    else:
        miss = []
        for c in cookies:
            nm = c.split("=")[0]; fl = c.lower(); lack = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in fl]
            if lack: miss.append(f"{nm}: missing {'/'.join(lack)}")
        res("HDR-007", "FAIL" if miss else "PASS", "; ".join(miss) if miss else f"{len(cookies)} cookie(s), all with Secure/HttpOnly/SameSite")
    res("HDR-008", "MANUAL", f"home page Cache-Control: {h.get('cache-control','none')}; private pages must be tested while signed in")
    leak = [f"{k}: {v}" for k, v in h.items() if k in ("server", "x-powered-by", "x-aspnet-version", "x-generator") and re.search(r"\d+\.\d+", v)]
    res("HDR-009", "WARN" if leak else "PASS", "; ".join(leak) if leak else "no version numbers in banner headers")
    probs = []
    for o in ("https://evil.example", "null"):
        try:
            _, ho, _ = req(host, 443, "/", {"Origin": o}); a = ho.get("access-control-allow-origin", ""); cr = ho.get("access-control-allow-credentials", "").lower() == "true"
            if a == o and cr: probs.append(f"reflects {o} with credentials")
            elif a == o: probs.append(f"reflects {o}")
            elif a == "*" and cr: probs.append("wildcard with credentials")
        except OSError: pass
    res("HDR-010", "FAIL" if any("credentials" in p for p in probs) else "WARN" if probs else "PASS", "; ".join(probs) if probs else "no CORS reflection on the home page (test API paths by hand)")

def main():
    ap = argparse.ArgumentParser(description="Everyday Security site checker"); ap.add_argument("site"); ap.add_argument("--json", action="store_true")
    a = ap.parse_args(); host = urlparse(a.site if "//" in a.site else "//" + a.site).hostname
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host): sys.exit("give a host name such as example.com")
    run(host); order = {"FAIL": 0, "WARN": 1, "MANUAL": 2, "PASS": 3}
    if a.json: print(json.dumps({"site": host, "checked": dt.datetime.utcnow().isoformat() + "Z", "results": R}, indent=2))
    else:
        print(f"\nEveryday Security · {host} · {dt.date.today()}\n" + "-" * 78)
        for r in R: print(f"{r['status']:6} {r['id']}  {r['detail'][:150]}")
        c = {k: sum(r["status"] == k for r in R) for k in order}; print("-" * 78 + f"\n{c['PASS']} pass · {c['WARN']} warn · {c['FAIL']} fail · {c['MANUAL']} manual\nHow to fix each item: kb/<pillar>/<ID>.md  ·  {REPO}  ·  {HOME}\n")
    sys.exit(1 if any(r["status"] == "FAIL" for r in R) else 0)
if __name__ == "__main__": main()
