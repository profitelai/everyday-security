import http.client, re, subprocess
from . import group
from ..context import UA

@group("mail", "MAIL-001", "MAIL-003", "MAIL-006")
def mail(ctx):
    ids = ("MAIL-001", "MAIL-003", "MAIL-006")
    if not ctx.has_dig: return [(i, "MANUAL", "dig is not installed") for i in ids]
    d = ctx.apex; mx = ctx.dig("MX", d); sends = bool(mx) and mx != ["0 ."]; out = []
    spf = [t for t in ctx.txt(d) if t.lower().startswith("v=spf1")]
    if len(spf) != 1: out.append(("MAIL-001", "FAIL" if sends else "WARN", f"{len(spf)} SPF records found at {d} (need exactly 1)"))
    else:
        n = ctx.spf_lookups(d); end = spf[0].split()[-1]
        out.append(("MAIL-001", "FAIL" if n > 10 or end.startswith("+") or "ptr" in spf[0] else "PASS" if end in ("-all", "~all") else "WARN", f"{spf[0][:90]} ; about {n} DNS lookups; ends {end}"))
    dm = [t for t in ctx.txt("_dmarc." + d) if t.lower().startswith("v=dmarc1")]
    if len(dm) != 1: out.append(("MAIL-003", "FAIL" if sends else "WARN", f"{len(dm)} DMARC records at _dmarc.{d}"))
    else:
        pol = re.search(r"\bp=(none|quarantine|reject)", dm[0], re.I); rua = "rua=" in dm[0].lower()
        out.append(("MAIL-003", "PASS" if pol and rua else "WARN", dm[0][:100] + ("" if rua else " ; no rua reporting address") + ("" if pol else " ; no valid p=")))
    sts = [t for t in ctx.txt("_mta-sts." + d) if t.startswith("v=STSv1")]; rpt = [t for t in ctx.txt("_smtp._tls." + d) if t.startswith("v=TLSRPTv1")]
    if not sends: out.append(("MAIL-006", "PASS", "domain does not receive mail (null or no MX): not applicable"))
    else:
        mode = "?"
        if sts:
            try:
                c = http.client.HTTPSConnection("mta-sts." + d, timeout=8); c.request("GET", "/.well-known/mta-sts.txt", headers={"User-Agent": UA}); body = c.getresponse().read(4096).decode("utf8", "ignore"); m = re.search(r"mode:\s*(\w+)", body); mode = m.group(1) if m else "?"
            except Exception: mode = "policy unreachable"
        out.append(("MAIL-006", "PASS" if sts and rpt and mode == "enforce" else "WARN", f"MTA-STS record: {'yes' if sts else 'no'} (policy mode {mode}); TLS-RPT record: {'yes' if rpt else 'no'}"))
    return out

@group("dns", "DNS-004", "DNS-005", "DNS-006")
def dns(ctx):
    ids = ("DNS-004", "DNS-005", "DNS-006")
    if not ctx.has_dig: return [(i, "MANUAL", "dig is not installed") for i in ids]
    d = ctx.apex; out = []; ns = [x.rstrip(".") for x in ctx.dig("NS", d)]
    out.append(("DNS-004", "PASS" if len(ns) >= 2 else "FAIL", f"{len(ns)} nameservers: {', '.join(ns[:4])} (independence of the providers needs a manual look)"))
    ds = ctx.dig("DS", d)
    try:
        fl = subprocess.run(["dig", "+dnssec", "+time=5", "+tries=1", "A", d, "@1.1.1.1"], capture_output=True, text=True, timeout=20).stdout.split("flags:")
        ad = len(fl) > 1 and "ad" in fl[1].split(";")[0].split()
    except Exception: ad = False
    out.append(("DNS-005", ("PASS" if ad else "FAIL") if ds else "WARN", ("DS record published and validation " + ("succeeds" if ad else "FAILS (broken chain?)")) if ds else "no DS record: DNSSEC not enabled (record the decision if your registrar or DNS host cannot do it)"))
    leaks = []
    for n in ns[:4]:
        try: o = subprocess.run(["dig", "AXFR", d, "@" + n, "+time=5", "+tries=1"], capture_output=True, text=True, timeout=25).stdout
        except Exception: continue
        if re.search(r"\sSOA\s", o) and "Transfer failed" not in o and "REFUSED" not in o.upper(): leaks.append(n)
    out.append(("DNS-006", "FAIL" if leaks else "PASS" if ns else "MANUAL", ("zone transfer allowed by " + ", ".join(leaks)) if leaks else f"all {len(ns)} nameservers refused a zone transfer"))
    return out
