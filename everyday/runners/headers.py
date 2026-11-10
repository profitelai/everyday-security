import re
from . import group
from ..context import fetch

IDS = tuple("HDR-%03d" % n for n in range(1, 11) if n != 8)   # HDR-008 lives in runners/outside.py

@group("headers", *IDS)
def headers(ctx):
    m = ctx.main(); out = []
    if "error" in m: return [(i, "MANUAL", "HTTPS page could not be fetched: " + m["error"]) for i in IDS]
    h, cookies = m["headers"], m["cookies"]
    if m.get("hops"): out.append(("NOTE", "INFO", f"{ctx.host} redirects; header checks below were made on https://{m['final_host']}/ after {m['hops']} redirect(s)"))
    hs = h.get("strict-transport-security", ""); x = re.search(r"max-age=(\d+)", hs, re.I)
    out.append(("HDR-001", "PASS" if x and int(x.group(1)) >= 15552000 else "WARN" if x else "FAIL", hs or "header missing"))
    csp = h.get("content-security-policy", "")
    if not csp: out.append(("HDR-002", "FAIL", "no Content-Security-Policy header"))
    else:
        sc = re.search(r"(?:^|;)\s*script-src\s+([^;]*)", csp) or re.search(r"(?:^|;)\s*default-src\s+([^;]*)", csp); sv = sc.group(1) if sc else ""
        bad = [k for k in ("'unsafe-inline'", "'unsafe-eval'") if k in sv] + (["wildcard"] if re.search(r"(^|\s)\*(\s|$)", sv) else [])
        if "'nonce-" in sv or "'strict-dynamic'" in sv: bad = [b for b in bad if b != "'unsafe-inline'"]
        out.append(("HDR-002", "WARN" if bad or not sc else "PASS", ("weak script policy: " + ", ".join(bad)) if bad else ("no script-src or default-src" if not sc else "script policy has no unsafe-inline/eval/wildcard")))
    fa = "frame-ancestors" in csp; xfo = h.get("x-frame-options", "").upper()
    out.append(("HDR-003", "PASS" if fa or xfo in ("DENY", "SAMEORIGIN") else "FAIL", f"frame-ancestors: {'yes' if fa else 'no'}; X-Frame-Options: {xfo or 'none'}"))
    out.append(("HDR-004", "PASS" if h.get("x-content-type-options", "").lower() == "nosniff" else "FAIL", h.get("x-content-type-options", "header missing")))
    rp = h.get("referrer-policy", "").lower()
    out.append(("HDR-005", "PASS" if rp.split(",")[-1].strip() in ("strict-origin-when-cross-origin", "same-origin", "no-referrer", "strict-origin", "origin-when-cross-origin") else "WARN", rp or "header missing (browser default applies)"))
    out.append(("HDR-006", "PASS" if h.get("permissions-policy") else "WARN", (h.get("permissions-policy") or "header missing")[:120]))
    if not cookies: out.append(("HDR-007", "PASS", "no cookies set on the home page (sign-in pages must be checked by hand)"))
    else:
        miss = []
        for c in cookies:
            lack = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in c.lower()]
            if lack: miss.append(f"{c.split('=')[0]}: missing {'/'.join(lack)}")
        out.append(("HDR-007", "FAIL" if miss else "PASS", "; ".join(miss) if miss else f"{len(cookies)} cookie(s), all with Secure/HttpOnly/SameSite"))
    leak = [f"{k}: {v}" for k, v in h.items() if k in ("server", "x-powered-by", "x-aspnet-version", "x-generator") and re.search(r"\d+\.\d+", v)]
    out.append(("HDR-009", "WARN" if leak else "PASS", "; ".join(leak) if leak else "no version numbers in banner headers"))
    probs = []
    for o in ("https://evil.example", "null"):
        try:
            ho = fetch(ctx.host, 443, "/", {"Origin": o}, timeout=ctx.timeout)["headers"]; a = ho.get("access-control-allow-origin", ""); cr = ho.get("access-control-allow-credentials", "").lower() == "true"
            if a == o and cr: probs.append(f"reflects {o} with credentials")
            elif a == o: probs.append(f"reflects {o}")
            elif a == "*" and cr: probs.append("wildcard with credentials")
        except OSError: pass
    out.append(("HDR-010", "FAIL" if any("credentials" in p for p in probs) else "WARN" if probs else "PASS", "; ".join(probs) if probs else "no CORS reflection on the home page (test API paths by hand)"))
    return out
