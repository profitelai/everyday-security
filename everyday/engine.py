"""Scan one site: built-in runners + data-pack rules, enriched from the knowledge base."""
import datetime as dt, time
from . import VERSION, registry
from .context import Context
from .model import score, tally
from .rules import run_rules
from .runners import load_all

def wanted(check_meta, only):
    """only = dict(ids=set, pillars=set, tags=set) or None."""
    if not only: return True
    if only.get("ids") and check_meta["id"] not in only["ids"]: return False
    if only.get("pillars") and check_meta.get("pillar") not in only["pillars"]: return False
    if only.get("tags") and not (set(check_meta.get("tags", [])) & only["tags"]): return False
    return True

def scan_site(site, checks, rules, only=None, deep=False, timeout=10):
    t0 = time.time(); host = site["host"]; ctx = Context(host, deep=deep or bool(site.get("allow_deep") and deep), timeout=timeout, subdomains=site.get("subdomains", []))
    results = []
    for name, ids, fn in load_all():
        if only and not any(wanted(checks.get(i, {"id": i}), only) for i in ids): continue
        try: out = fn(ctx)
        except Exception as ex: out = [(i, "MANUAL", f"runner error: {type(ex).__name__}: {ex}") for i in ids]
        for cid, status, detail in out:
            meta = checks.get(cid, {"id": cid, "title": "Scan note", "pillar": "scan", "severity": "info", "tags": []})
            if only and cid != "NOTE" and not wanted(meta, only): continue
            results.append({"id": cid, "status": status, "detail": detail, "severity": meta.get("severity", "info"), "title": meta.get("title", cid), "pillar": meta.get("pillar", "scan"),
                            "tags": meta.get("tags", []), "kb": meta.get("file"), "source_type": "builtin"})
    stats = {"evaluated": 0, "hits": 0, "skipped": 0, "expired": 0}
    if rules and not (only and (only.get("ids") or only.get("pillars"))):
        sel = [r for r in rules if not only or not only.get("tags") or set(r.get("tags", [])) & only["tags"]]
        f, stats = run_rules(ctx, sel, dt.date.today().isoformat())
        for x in f:
            link = checks.get(x.get("check") or "", {}); rt = registry.RULE_TYPES[x["rule_type"]]
            x.update(pillar=link.get("pillar") or rt[2], tags=link.get("tags", []), kb=link.get("file"))
            results.append(x)
    s, g = score(results)
    return {"host": host, "name": site.get("name", host), "tags": site.get("tags", []), "owner": site.get("owner", ""), "criticality": site.get("criticality", ""),
            "deep": ctx.deep, "started": dt.datetime.utcnow().isoformat() + "Z", "seconds": round(time.time() - t0, 1), "score": s, "grade": g,
            "tally": tally(results), "rules": stats, "results": results}
