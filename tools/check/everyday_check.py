#!/usr/bin/env python3
"""Everyday Security site checker: runs the automatable checks from kb/ against one website, from the outside.

    python3 tools/check/everyday_check.py example.com
    python3 tools/check/everyday_check.py https://example.com --json

Only a few ordinary requests are made (one HTTPS page, one HTTP page, one TLS handshake per protocol, DNS lookups for
CAA, SPF, DMARC, MTA-STS, NS and DS, one zone-transfer attempt per nameserver, two requests carrying a test Origin header). It never probes paths, ports or logins.
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
    try:
        st, h, cookies = req(host, 443); fhost, hops = host, 0
        while st in (301, 302, 303, 307, 308) and h.get("location", "").lower().startswith("https://") and hops < 3:
            u = urlparse(h["location"]); fhost, hops = u.hostname, hops + 1; st, h, cookies = req(u.hostname, 443, (u.path or "/") + ("?" + u.query if u.query else ""))
        if hops: res("NOTE", "INFO", f"{host} redirects; header checks below were made on https://{fhost}/ after {hops} redirect(s)")
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


# ---------------- DNS and mail checks (dig only) ----------------
TWO = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.nz", "com.br", "co.jp", "co.za", "com.mx", "com.cn", "co.in"}
def apex_of(host):
    p = host.split("."); return ".".join(p[-3:]) if ".".join(p[-2:]) in TWO and len(p) >= 3 else ".".join(p[-2:])
def dig(*a):
    try: return subprocess.run(["dig", "+short", "+time=5", "+tries=1", *a], capture_output=True, text=True, timeout=20).stdout.strip().splitlines()
    except Exception: return []
def txt(name): return [l.replace('" "', "").strip('"') for l in dig("TXT", name)]
def spf_lookups(domain, depth=0, seen=None):
    seen = seen or set()
    if depth > 10 or domain in seen: return 0
    seen.add(domain); recs = [t for t in txt(domain) if t.lower().startswith("v=spf1")]
    if not recs: return 0
    n = 0
    for term in recs[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")): n += 1 + spf_lookups(re.split("[:=]", t, 1)[1], depth + 1, seen)
        elif t.split(":")[0].split("/")[0] in ("a", "mx", "ptr", "exists"): n += 1
    return n
def dns_mail(host):
    if not shutil.which("dig"):
        for i in ("MAIL-001", "MAIL-003", "MAIL-006", "DNS-004", "DNS-005", "DNS-006"): res(i, "MANUAL", "dig is not installed")
        return
    d = apex_of(host); mx = dig("MX", d); sends = bool(mx) and mx != ["0 ."]
    spf = [t for t in txt(d) if t.lower().startswith("v=spf1")]
    if len(spf) != 1: res("MAIL-001", "FAIL" if sends else "WARN", f"{len(spf)} SPF records found at {d} (need exactly 1)")
    else:
        n = spf_lookups(d); end = spf[0].split()[-1]
        res("MAIL-001", "FAIL" if n > 10 or end.startswith("+") or "ptr" in spf[0] else "PASS" if end in ("-all", "~all") else "WARN", f"{spf[0][:90]} ; about {n} DNS lookups; ends {end}")
    dm = [t for t in txt("_dmarc." + d) if t.lower().startswith("v=dmarc1")]
    if len(dm) != 1: res("MAIL-003", "FAIL" if sends else "WARN", f"{len(dm)} DMARC records at _dmarc.{d}")
    else:
        pol = re.search(r"\bp=(none|quarantine|reject)", dm[0], re.I); rua = "rua=" in dm[0].lower()
        res("MAIL-003", "PASS" if pol and rua else "WARN", f"{dm[0][:100]}" + ("" if rua else " ; no rua reporting address") + ("" if pol else " ; no valid p="))
    sts = [t for t in txt("_mta-sts." + d) if t.startswith("v=STSv1")]; rpt = [t for t in txt("_smtp._tls." + d) if t.startswith("v=TLSRPTv1")]
    if not sends: res("MAIL-006", "PASS", "domain does not receive mail (null or no MX): not applicable")
    else:
        mode = "?"
        if sts:
            try:
                c = http.client.HTTPSConnection("mta-sts." + d, timeout=8); c.request("GET", "/.well-known/mta-sts.txt", headers={"User-Agent": UA}); body = c.getresponse().read(4096).decode("utf8", "ignore"); m = re.search(r"mode:\s*(\w+)", body); mode = m.group(1) if m else "?"
            except Exception: mode = "policy unreachable"
        res("MAIL-006", "PASS" if sts and rpt and mode == "enforce" else "WARN", f"MTA-STS record: {'yes' if sts else 'no'} (policy mode {mode}); TLS-RPT record: {'yes' if rpt else 'no'}")
    ns = [x.rstrip(".") for x in dig("NS", d)]
    res("DNS-004", "PASS" if len(ns) >= 2 else "FAIL", f"{len(ns)} nameservers: {', '.join(ns[:4])} (independence of the providers needs a manual look)")
    ds = dig("DS", d); ad = "ad" in " ".join(subprocess.run(["dig", "+dnssec", "+time=5", "+tries=1", "A", d, "@1.1.1.1"], capture_output=True, text=True, timeout=20).stdout.split("flags:")[1:2]).split(";")[0].split() if shutil.which("dig") else False
    res("DNS-005", ("PASS" if ad else "FAIL") if ds else "WARN", ("DS record published and validation " + ("succeeds" if ad else "FAILS (broken chain?)")) if ds else "no DS record: DNSSEC not enabled (record the decision if your registrar or DNS host cannot do it)")
    leaks = []
    for n in ns[:4]:
        out = subprocess.run(["dig", "AXFR", d, "@" + n, "+time=5", "+tries=1"], capture_output=True, text=True, timeout=25).stdout
        if re.search(r"\sSOA\s", out) and "Transfer failed" not in out and "REFUSED" not in out.upper(): leaks.append(n)
    res("DNS-006", "FAIL" if leaks else "PASS" if ns else "MANUAL", ("zone transfer allowed by " + ", ".join(leaks)) if leaks else f"all {len(ns)} nameservers refused a zone transfer")

def main():
    ap = argparse.ArgumentParser(description="Everyday Security site checker"); ap.add_argument("site"); ap.add_argument("--json", action="store_true")
    a = ap.parse_args(); host = urlparse(a.site if "//" in a.site else "//" + a.site).hostname
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host): sys.exit("give a host name such as example.com")
    run(host); dns_mail(host); order = {"FAIL": 0, "WARN": 1, "MANUAL": 2, "PASS": 3, "INFO": 4}
    if a.json: print(json.dumps({"site": host, "checked": dt.datetime.utcnow().isoformat() + "Z", "results": R}, indent=2))
    else:
        print(f"\nEveryday Security · {host} · {dt.date.today()}\n" + "-" * 78)
        for r in R: print(f"{r['status']:6} {r['id']}  {r['detail'][:150]}")
        c = {k: sum(r["status"] == k for r in R) for k in order}; print("-" * 78 + f"\n{c['PASS']} pass · {c['WARN']} warn · {c['FAIL']} fail · {c['MANUAL']} manual\nHow to fix each item: kb/<pillar>/<ID>.md  ·  {REPO}  ·  {HOME}\n")
    sys.exit(1 if any(r["status"] == "FAIL" for r in R) else 0)
if __name__ == "__main__": main()
