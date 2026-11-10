"""Scan many sites in parallel from an inventory file."""
import concurrent.futures as cf, datetime as dt, json, os
from . import VERSION, registry
from .engine import scan_site

def load_sites(path):
    data = json.load(open(path, encoding="utf-8")); sites = data["sites"] if isinstance(data, dict) else data
    for s in sites:
        if "host" not in s: raise ValueError(f"site without host: {s}")
        s["host"] = s["host"].lower().strip()
    return sites

def scan_fleet(sites, only=None, deep=False, workers=4, include_pending=False, extra_pack_dirs=(), progress=None):
    checks = registry.load_checks(); rules, probs = registry.load_packs(extra_pack_dirs, include_pending=include_pending)
    run = {"version": VERSION, "pack_hash": registry.pack_hash(rules), "rules_loaded": len(rules), "started": dt.datetime.utcnow().isoformat() + "Z", "deep": deep, "sites": []}
    def one(s):
        try: return scan_site(s, checks, rules, only, deep)
        except Exception as ex:
            return {"host": s["host"], "name": s.get("name", s["host"]), "tags": s.get("tags", []), "score": 0, "grade": "F", "tally": {}, "rules": {}, "seconds": 0,
                    "results": [{"id": "SCAN-ERR", "status": "FAIL", "detail": f"scan failed: {ex}", "severity": "high", "title": "Scan error", "pillar": "scan", "tags": []}]}
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(one, s): s for s in sites}
        for f in cf.as_completed(futs):
            r = f.result(); run["sites"].append(r)
            if progress: progress(r)
    run["sites"].sort(key=lambda r: (r["score"], r["host"])); run["finished"] = dt.datetime.utcnow().isoformat() + "Z"
    return run
