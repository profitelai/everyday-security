"""Data-pack evaluators. A rule is data (JSON); evaluating it needs no code change. A matching rule yields one finding."""
import random, re, string, time
from .context import fetch
from .model import status_for_hit

def _ver(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:4])

def _res(rule, status, detail):
    return {"id": rule["id"], "status": status, "detail": detail, "severity": rule["severity"], "title": rule["title"], "source_type": "pack", "rule_type": rule["type"], "check": rule.get("check"), "pack": rule.get("_pack")}

def _expired(rule, today):
    return bool(rule.get("expires")) and rule["expires"] < today

def eval_http_header(ctx, rule):
    m = ctx.main()
    if "error" in m: return None
    v = m["headers"].get(rule["header"].lower()); e = rule["expect"]
    hit = (e == "present" and v is None) or (e == "absent" and v is not None) or (e == "equals" and (v or "").lower() != rule["value"].lower()) \
        or (e == "regex" and not re.search(rule["value"], v or "", re.I)) or (e == "not_regex" and v is not None and re.search(rule["value"], v, re.I) is not None)
    if not hit: return False
    return _res(rule, status_for_hit(rule["severity"]), f"{rule['header']}: {v if v is not None else 'missing'} ({rule['expect']}{' ' + rule['value'] if rule.get('value') else ''})")

def eval_banner_version(ctx, rule):
    m = ctx.main()
    if "error" in m: return None
    v = m["headers"].get(rule["header"].lower())
    if not v: return False
    g = re.search(rule["regex"], v, re.I)
    if not g: return False
    ver = g.group(1) if g.groups() else g.group(0)
    bad = (rule.get("bad_below") and _ver(ver) < _ver(rule["bad_below"])) or (ver in (rule.get("bad_versions") or []))
    if not bad: return False
    extra = (" ; " + ", ".join(rule["cve"])) if rule.get("cve") else ""
    return _res(rule, status_for_hit(rule["severity"]), f"{rule['header']}: {v} (version {ver} is flagged: {('below ' + rule['bad_below']) if rule.get('bad_below') else 'listed'}){extra}")

def eval_dns_record(ctx, rule):
    if not ctx.has_dig: return None
    name = rule["name"].format(apex=ctx.apex, host=ctx.host)
    vals = ctx.txt(name) if rule["rtype"].upper() == "TXT" else ctx.dig(rule["rtype"].upper(), name); e = rule["expect"]; joined = " | ".join(vals)
    hit = (e == "present" and not vals) or (e == "absent" and bool(vals)) or (e == "regex" and not re.search(rule["value"], joined, re.I)) or (e == "not_regex" and bool(vals) and re.search(rule["value"], joined, re.I) is not None)
    return _res(rule, status_for_hit(rule["severity"]), f"{rule['rtype']} {name}: {joined[:100] or 'none'}") if hit else False

class PathProber:
    """Baseline-aware path probing (deep scans only). A catch-all site that answers 200 to every path would otherwise
    make every probe look like a hit, so a random path is fetched first and used as the comparison."""
    def __init__(self, ctx):
        self.ctx = ctx; rnd = "/" + "".join(random.choice(string.ascii_lowercase) for _ in range(14)) + ".nonexistent"
        try: b = fetch(ctx.host, 443, rnd, timeout=ctx.timeout, limit=4096); self.base = (b["status"], len(b["body"]))
        except OSError: self.base = None
        self.catch_all = bool(self.base and self.base[0] == 200)
    def __call__(self, ctx, rule):
        if not ctx.deep: return None
        try: r = fetch(ctx.host, 443, rule["path"], timeout=ctx.timeout, limit=8192)
        except OSError: return None
        body = r["body"].decode("utf8", "ignore"); ok_status = r["status"] in (rule.get("expect_status") or [200])
        found = ok_status and (not rule.get("body_regex") or re.search(rule["body_regex"], body, re.M | re.I) is not None) \
            and not (rule.get("not_body_regex") and re.search(rule["not_body_regex"], body, re.I | re.M)) \
            and not (self.catch_all and not rule.get("body_regex") and r["status"] == 200)
        time.sleep(0.15)
        if rule.get("finding_when", "found") == "found" and found: return _res(rule, status_for_hit(rule["severity"]), f"GET {rule['path']} answered {r['status']}" + (" and matched the signature" if rule.get("body_regex") else ""))
        if rule.get("finding_when") == "missing" and not found: return _res(rule, status_for_hit(rule["severity"]), f"GET {rule['path']} answered {r['status']} (expected to be present)")
        return False

def eval_takeover(ctx, rule):
    out = []
    for sub in ctx.subdomains:
        cn = [c.rstrip(".").lower() for c in ctx.dig("CNAME", sub)]
        if not any(c.endswith(rule["cname_suffix"].lower()) for c in cn): continue
        for port in (443, 80):
            try: body = fetch(sub, port, "/", timeout=ctx.timeout, limit=16384)["body"].decode("utf8", "ignore")
            except OSError: continue
            if rule["fingerprint"].lower() in body.lower(): out.append(_res(rule, status_for_hit(rule["severity"]), f"{sub} -> {cn[0]} shows the unclaimed-service message"))
            break
    return out or False

EVALUATORS = {"http_header": eval_http_header, "banner_version": eval_banner_version, "dns_record": eval_dns_record, "takeover": eval_takeover}

def run_rules(ctx, rules, today):
    """-> (findings, stats). stats = evaluated / hits / skipped / expired counts. Never raises on a bad rule."""
    prober = None; findings = []; st = {"evaluated": 0, "hits": 0, "skipped": 0, "expired": 0}
    for r in rules:
        if _expired(r, today): st["expired"] += 1; continue
        try:
            if r["type"] == "path_probe":
                if not ctx.deep: st["skipped"] += 1; continue
                prober = prober or PathProber(ctx); res = prober(ctx, r)
            else: res = EVALUATORS[r["type"]](ctx, r)
        except Exception as ex: st["skipped"] += 1; continue
        if res is None: st["skipped"] += 1; continue
        st["evaluated"] += 1
        for x in (res if isinstance(res, list) else [res] if res else []): findings.append(x); st["hits"] += 1
    return findings, st
