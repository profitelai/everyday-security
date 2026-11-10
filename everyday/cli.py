"""Command line: python3 -m everyday <command>   (or ./everyday.py)"""
import argparse, datetime as dt, json, os, subprocess, sys
from . import HOME, REPO, VERSION, fleet, ingest, registry, report, store
from .runners import load_all, provided_ids

AUTO = {"yes": "auto", "host": "server"}
R = registry.ROOT; RUNS = os.path.join(R, "reports", "runs")

def parse_only(a):
    o = {}
    for k in ("ids", "pillars", "tags"):
        v = getattr(a, k, None)
        if v: o[k] = {x.strip() for x in v.split(",") if x.strip()}
    return o or None

def _publish(run, as_json):
    rid = dt.datetime.now().strftime("%Y%m%d-%H%M%S"); d = os.path.join(RUNS, rid); os.makedirs(d, exist_ok=True)
    store.save(run, rid); df = store.diff(rid, store.previous_run(rid))
    json.dump(run, open(os.path.join(d, "results.json"), "w"), indent=1)
    open(os.path.join(d, "report.html"), "w").write(report.to_html(run, rid, df)); open(os.path.join(d, "report.md"), "w").write(report.to_markdown(run, rid, df)); open(os.path.join(d, "findings.csv"), "w").write(report.to_csv(run))
    open(os.path.join(R, "reports", "latest.txt"), "w").write(rid)
    if as_json: print(json.dumps(run, indent=1))
    else: print(f"\nReport: {os.path.join(d, 'report.html')}\n        {os.path.join(d, 'report.md')}  ·  {os.path.join(d, 'findings.csv')}\n{HOME}")

def cmd_audit_host(a):
    from . import hostaudit
    r = hostaudit.audit_result(a.label)
    run = {"version": VERSION, "pack_hash": "", "rules_loaded": 0, "started": r["started"], "deep": False, "sites": [r], "finished": r["started"]}
    _publish(run, a.json)
    for x in r["results"]: print(f"  {x['status']:6} {x['id']:8} {x['detail'][:110]}")
    return 1 if r["tally"].get("FAIL") and a.fail_on_fail else 0

def cmd_scan(a):
    if a.sites: sites = fleet.load_sites(a.sites)
    elif a.site: sites = [{"host": h.split("//")[-1].strip("/").split("/")[0], "tags": []} for h in a.site]
    else: sys.exit("give site names or --sites FILE")
    if a.tag: sites = [s for s in sites if set(a.tag.split(",")) & set(s.get("tags", []))]
    if not sites: sys.exit("no sites selected")
    if a.deep and not a.i_own_these: sys.exit("--deep probes sensitive paths; add --i-own-these to confirm you own or may test every selected site")
    if a.deep and a.sites: sites = [s for s in sites if s.get("allow_deep")] or sys.exit("no selected site has allow_deep: true in the inventory")
    if not a.quiet: print(f"Scanning {len(sites)} site(s){' (deep)' if a.deep else ''} ...", file=sys.stderr)
    run = fleet.scan_fleet(sites, parse_only(a), a.deep, a.workers, a.include_pending, progress=(None if a.quiet else lambda r: print(f"  {r['grade']} {r['score']:>3}  {r['host']}  ({r['tally'].get('FAIL',0)} fail, {r['tally'].get('WARN',0)} warn, {r['seconds']}s)", file=sys.stderr)))
    _publish(run, a.json)
    return 1 if any(s["tally"].get("FAIL") for s in run["sites"]) and a.fail_on_fail else 0

def cmd_list(a):
    if a.what == "checks":
        for i, c in sorted(registry.load_checks().items()): print(f"{i:9} {c['pillar']:22} {c['severity']:8} {AUTO.get(c['automated'], 'manual'):6} {c['title'][:70]}")
    elif a.what == "packs":
        rules, _ = registry.load_packs(include_pending=True)
        for r in rules: print(f"{r['id']:11} {r['type']:15} {r['severity']:8} {r['status']:9} {r['title'][:70]}")
    elif a.what == "runs":
        for r in store.runs(): print(*r)
    return 0

def cmd_validate(a):
    bad = 0; chk = registry.load_checks(); rules, probs = registry.load_packs(include_pending=True)
    for f, i, errs in probs: print(f"PACK {os.path.basename(f)} {i}: {'; '.join(errs)}"); bad += 1
    missing = sorted(i for i, c in chk.items() if c["automated"] == "yes" and i not in provided_ids())
    for i in missing: print(f"KB check {i} says automated: yes but no runner provides it"); bad += 1
    from . import hostaudit
    for i in sorted(i for i, c in chk.items() if c["automated"] == "host" and i not in hostaudit.HOST_IDS): print(f"KB check {i} says automated: host but hostaudit does not judge it"); bad += 1
    p = subprocess.run([sys.executable, os.path.join(R, "tools", "kb", "lint.py")], capture_output=True, text=True); print(p.stdout.strip()); bad += p.returncode != 0
    print(f"{len(chk)} checks, {len(rules)} data rules (incl. pending), {len(probs)} invalid rules, {len(missing)} runner gaps"); return 1 if bad else 0

def cmd_ingest(a):
    rows = ingest.read_rows(a.file)
    if a.type == "check": res = ingest.ingest_checks(rows); print(f"checks created: {len(res['added'])} ({', '.join(res['added'][:10])}); invalid: {res['invalid']}"); 
    else:
        res = ingest.ingest_rules(a.type, rows, a.source, a.license, a.author); print(f"added {res['added']} (pending), duplicates {res['duplicates']}, invalid {res['invalid']}" + (f"\nwritten: {res['file']}" if res["file"] else ""))
    for raw, errs in res["bad"][:15]: print("  invalid:", json.dumps(raw)[:100], "->", "; ".join(errs))
    if a.type == "check" and res["added"]: subprocess.run([sys.executable, os.path.join(R, "tools", "kb", "build_index.py")])
    return 0

def cmd_approve(a):
    dst, n = ingest.approve(a.file, a.reviewer); print(f"approved {n} rules -> {dst}"); return 0

def cmd_stats(a):
    chk = registry.load_checks(); rules, _ = registry.load_packs(include_pending=True); inc = [r for r in rules if r["status"] == "pending"]
    d = {"version": VERSION, "pillars": len({c["pillar"] for c in chk.values()}), "checks": len(chk), "automated_checks": sum(c["automated"] == "yes" for c in chk.values()),
         "rules_approved": sum(r["status"] == "approved" for r in rules), "rules_pending": len(inc), "rules_by_type": {t: sum(r["type"] == t for r in rules) for t in registry.RULE_TYPES}, "sources": len(registry.source_ids())}
    print(json.dumps(d, indent=1)); return 0

def main(argv=None):
    ap = argparse.ArgumentParser(prog="everyday", description=f"Everyday Security {VERSION} by Profitell Security Consulting · {HOME}"); sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("scan", help="scan one or many sites"); s.add_argument("site", nargs="*"); s.add_argument("--sites", help="inventory JSON file"); s.add_argument("--tag"); s.add_argument("--ids"); s.add_argument("--pillars"); s.add_argument("--tags")
    s.add_argument("--deep", action="store_true"); s.add_argument("--i-own-these", action="store_true"); s.add_argument("--workers", type=int, default=4); s.add_argument("--include-pending", action="store_true"); s.add_argument("--json", action="store_true"); s.add_argument("--quiet", action="store_true"); s.add_argument("--fail-on-fail", action="store_true"); s.set_defaults(f=cmd_scan)
    h = sp.add_parser("audit-host", help="read-only audit of THIS server (run it on the server, ideally as root)"); h.add_argument("--label", default=os.uname().nodename); h.add_argument("--json", action="store_true"); h.add_argument("--fail-on-fail", action="store_true"); h.set_defaults(f=cmd_audit_host)
    l = sp.add_parser("list"); l.add_argument("what", choices=["checks", "packs", "runs"]); l.set_defaults(f=cmd_list)
    v = sp.add_parser("validate", help="validate the knowledge base, data packs and runners"); v.set_defaults(f=cmd_validate)
    i = sp.add_parser("ingest", help="add new data points as PENDING"); i.add_argument("--type", required=True, choices=list(registry.RULE_TYPES) + ["check"]); i.add_argument("--file", required=True); i.add_argument("--source", default=""); i.add_argument("--license", default="unspecified"); i.add_argument("--author", default="Profitell Security Consulting"); i.set_defaults(f=cmd_ingest)
    p = sp.add_parser("approve", help="move a pending file into the live packs"); p.add_argument("file"); p.add_argument("--reviewer", required=True); p.set_defaults(f=cmd_approve)
    t = sp.add_parser("stats"); t.set_defaults(f=cmd_stats)
    a = ap.parse_args(argv); return a.f(a)

if __name__ == "__main__": sys.exit(main())
