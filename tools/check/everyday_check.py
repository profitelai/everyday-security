#!/usr/bin/env python3
"""Single-site checker (kept for compatibility). Same engine as `python3 -m everyday scan`.
    python3 tools/check/everyday_check.py example.com [--json]     Profitell Security Consulting · https://www.profitell.com/"""
import argparse, datetime as dt, json, os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from everyday import HOME, REPO, registry
from everyday.engine import scan_site

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("site"); ap.add_argument("--json", action="store_true"); a = ap.parse_args()
    from urllib.parse import urlparse
    host = urlparse(a.site if "//" in a.site else "//" + a.site).hostname
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host): sys.exit("give a host name such as example.com")
    rules, _ = registry.load_packs(); s = scan_site({"host": host}, registry.load_checks(), rules)
    res = [{"id": r["id"], "status": r["status"], "detail": r["detail"]} for r in s["results"]]
    if a.json: print(json.dumps({"site": host, "checked": dt.datetime.utcnow().isoformat() + "Z", "score": s["score"], "grade": s["grade"], "results": res}, indent=2))
    else:
        print(f"\nEveryday Security · {host} · {dt.date.today()} · grade {s['grade']} ({s['score']})\n" + "-" * 78)
        for r in res: print(f"{r['status']:6} {r['id']:9} {r['detail'][:140]}")
        t = s["tally"]; print("-" * 78 + f"\n{t['PASS']} pass · {t['WARN']} warn · {t['FAIL']} fail · {t['MANUAL']} manual\nFix guides: kb/<pillar>/<ID>.md · {REPO} · {HOME}\n")
    sys.exit(1 if s["tally"]["FAIL"] else 0)
if __name__ == "__main__": main()
