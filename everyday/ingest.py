"""Bulk intake of new data points. Everything arrives as PENDING in data/incoming/ with full provenance, is validated and
de-duplicated, and only goes live after `approve` (a human step). Check files (kb/*.md) are created as drafts."""
import csv, datetime as dt, glob, json, os, re
from . import registry

LISTS = {"expect_status", "tags", "cve", "bad_versions", "standards", "sources"}
KEYS = {
    "http_header": lambda r: ("http_header", r.get("header", "").lower(), r.get("expect"), (r.get("value") or "").lower()),
    "path_probe": lambda r: ("path_probe", r.get("path"), r.get("finding_when", "found")),
    "banner_version": lambda r: ("banner_version", r.get("header", "").lower(), r.get("regex")),
    "takeover": lambda r: ("takeover", r.get("cname_suffix", "").lower()),
    "dns_record": lambda r: ("dns_record", r.get("name"), r.get("rtype", "").upper(), r.get("expect"), r.get("value") or ""),
}

def read_rows(path):
    if path.endswith(".csv"): return list(csv.DictReader(open(path, encoding="utf-8-sig", newline="")))
    if path.endswith(".jsonl"): return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    d = json.loads(registry._read(path)); return d["rules"] if isinstance(d, dict) else d

def normalize(row):
    r = {}
    for k, v in row.items():
        if v is None: continue
        k = k.strip()
        if isinstance(v, str):
            v = v.strip()
            if v == "": continue
            if k in LISTS: v = [x.strip() for x in v.split("|") if x.strip()]
            if k == "expect_status": v = [int(x) for x in v if str(x).isdigit()]
        r[k] = v
    return r

def existing(root=registry.ROOT):
    ids, keys = set(), set()
    for d in ("packs", "incoming"):
        for f in glob.glob(os.path.join(root, "data", d, "*.json")):
            try: rules = json.loads(registry._read(f)).get("rules", [])
            except Exception: continue
            for r in rules:
                ids.add(r.get("id"))
                if r.get("type") in KEYS: keys.add(KEYS[r["type"]](r))
    return ids, keys

def next_id(prefix, ids):
    n = max([int(m.group(1)) for i in ids if i and (m := re.fullmatch(re.escape(prefix) + r"-(\d+)", i))] or [0]); return f"{prefix}-{n+1:04d}"

def ingest_rules(rtype, rows, source, license_, author, root=registry.ROOT, stamp=None):
    if rtype not in registry.RULE_TYPES: raise ValueError(f"type must be one of {', '.join(registry.RULE_TYPES)}")
    ids, keys = existing(root); src, chk = registry.source_ids(root), registry.load_checks(root); today = dt.date.today().isoformat()
    added, dups, bad = [], [], []
    for raw in rows:
        r = normalize(raw); r["type"] = rtype; r.setdefault("source", source); r.setdefault("license", license_); r.setdefault("author", author); r.setdefault("added", today); r["status"] = "pending"
        r.setdefault("severity", "low"); r.setdefault("title", r.get("path") or r.get("header") or r.get("name") or r.get("cname_suffix") or "")
        if rtype == "http_header" and "expect" not in r: r["expect"] = "present"
        if rtype == "path_probe": r.setdefault("expect_status", [200])
        if not r.get("id"): r["id"] = next_id(registry.RULE_TYPES[rtype][0], ids)
        errs = registry.validate_rule(r, src, chk)
        if errs: bad.append((raw, errs)); continue
        k = KEYS[rtype](r)
        if k in keys or r["id"] in ids: dups.append((raw, "already present")); continue
        keys.add(k); ids.add(r["id"]); added.append(r)
    out = None
    if added:
        os.makedirs(os.path.join(root, "data", "incoming"), exist_ok=True)
        out = os.path.join(root, "data", "incoming", f"{rtype}-{stamp or dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
        with open(out, "w") as fh: json.dump({"pack": os.path.basename(out)[:-5], "version": "1", "rules": added}, fh, indent=1, ensure_ascii=False)
    return {"file": out, "added": len(added), "duplicates": len(dups), "invalid": len(bad), "bad": bad, "dups": dups}

def approve(path, reviewer, root=registry.ROOT):
    d = json.loads(registry._read(path)); src, chk = registry.source_ids(root), registry.load_checks(root); today = dt.date.today().isoformat()
    for r in d["rules"]:
        r["status"] = "approved"; r["reviewed_by"] = reviewer; r["approved"] = today
        errs = registry.validate_rule(r, src, chk)
        if errs: raise ValueError(f"{r.get('id')}: {', '.join(errs)}")
    dst = os.path.join(root, "data", "packs", os.path.basename(path))
    with open(dst, "w") as fh: json.dump(d, fh, indent=1, ensure_ascii=False)
    os.remove(path); return dst, len(d["rules"])

SECTIONS = [("why", "Why it matters"), ("test", "How to test"), ("pass", "Pass criteria"), ("fix", "Fix"), ("risk", "Risk and rollback")]

def ingest_checks(rows, root=registry.ROOT):
    src, chk = registry.source_ids(root), registry.load_checks(root); today = dt.date.today().isoformat(); added, bad = [], []
    for raw in rows:
        r = normalize(raw); errs = []
        for k in ["id", "pillar", "title", "severity", "sources", "tags", "target", "method", "tool", "why", "test", "pass", "fix", "risk"]:
            if not r.get(k): errs.append(f"missing {k}")
        if r.get("id") and not re.fullmatch(r"[A-Z]{2,6}-\d{3}", r["id"]): errs.append("id must look like ABC-001")
        if r.get("id") in chk: errs.append("id already exists")
        if r.get("pillar") and not re.fullmatch(r"[a-z0-9-]+", r["pillar"]): errs.append("pillar must be lowercase-hyphen")
        if r.get("severity") and r["severity"] not in registry.SEVERITIES: errs.append("bad severity")
        for s in r.get("sources", []):
            if s not in src: errs.append(f"unknown source {s}")
        if errs: bad.append((raw, errs)); continue
        fm = ["---", f"id: {r['id']}", f"title: \"{r['title']}\"", f"pillar: {r['pillar']}", f"severity: {r['severity']}", f"standards: [{', '.join(r.get('standards', []))}]",
              f"sources: [{', '.join(r['sources'])}]", f"tags: [{', '.join(r['tags'])}]", f"target: {r['target']}", f"method: {r['method']}", f"tool: {r['tool']}", f"automated: {r.get('automated', 'no')}",
              "status: draft", f"drafted: {today}", f"author: {r.get('author', 'Profitell Security Consulting')}", "---", ""]
        body = [f"# {r['id']} · {r['title']}", ""] + sum([[f"## {h}", r[k], ""] for k, h in SECTIONS], [])
        p = os.path.join(root, "kb", r["pillar"], r["id"] + ".md"); os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write("\n".join(fm + body)); added.append(r["id"]); chk[r["id"]] = {}
    return {"added": added, "invalid": len(bad), "bad": bad}
