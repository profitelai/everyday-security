"""Loads the knowledge base (kb/*.md front matter) and the data packs (data/packs/*.json), and validates both."""
import glob, hashlib, json, os, re

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PACK_DIR = os.path.join(ROOT, "data", "packs"); INCOMING_DIR = os.path.join(ROOT, "data", "incoming")
RULE_TYPES = {
    # type: (id prefix, required fields beyond the common ones, default pillar)
    "http_header":    ("HDR-R", ["header", "expect"], "http-headers"),
    "path_probe":     ("PRB",   ["path"], "web-app"),
    "banner_version": ("VER",   ["header", "regex"], "server-hardening"),
    "takeover":       ("TKO",   ["cname_suffix", "fingerprint"], "dns"),
    "dns_record":     ("DNR",   ["name", "rtype", "expect"], "dns"),
}
COMMON = ["id", "type", "title", "severity", "source", "license", "added", "status"]
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("approved", "pending", "rejected")

def _read(p):
    with open(p, encoding="utf-8") as f: return f.read()

def parse_front(text):
    m = re.match(r"---\n(.*?)\n---\n(.*)", text, re.S)
    if not m: return None, text
    fm = {}
    for l in m.group(1).splitlines():
        if ": " in l:
            k, v = l.split(": ", 1); v = v.strip()
            fm[k] = [x.strip() for x in v[1:-1].split(",") if x.strip()] if v.startswith("[") else v.strip('"')
    return fm, m.group(2)

def load_checks(root=ROOT):
    """Every knowledge-base check, keyed by ID."""
    out = {}
    for p in sorted(glob.glob(os.path.join(root, "kb", "*", "*.md"))):
        fm, _ = parse_front(_read(p))
        if fm and "id" in fm: fm["file"] = os.path.relpath(p, root); out[fm["id"]] = fm
    return out

def source_ids(root=ROOT):
    files = [os.path.join(root, "docs", "sources.md")] + sorted(glob.glob(os.path.join(root, "docs", "sources.d", "*.md")))
    return {i for f in files if os.path.exists(f) for i in re.findall(r"^\| (S-[A-Z0-9\-]+) \|", _read(f), re.M)}

def validate_rule(r, sources=None, checks=None):
    """Return a list of problems (empty = valid)."""
    e = []
    t = r.get("type")
    if t not in RULE_TYPES: return [f"unknown type {t!r}"]
    for k in COMMON + RULE_TYPES[t][1]:
        if r.get(k) in (None, "", []): e.append(f"missing {k}")
    if r.get("severity") not in SEVERITIES: e.append("bad severity")
    if r.get("status") not in STATUSES: e.append("bad status")
    if r.get("id") and not str(r["id"]).startswith(RULE_TYPES[t][0] + "-"): e.append(f"id must start with {RULE_TYPES[t][0]}-")
    if r.get("added") and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r["added"])): e.append("added must be YYYY-MM-DD")
    if r.get("expires") and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r["expires"])): e.append("expires must be YYYY-MM-DD")
    s = str(r.get("source", ""))
    if s and not (s.startswith("http://") or s.startswith("https://") or re.fullmatch(r"S-[A-Z0-9\-]+", s)): e.append("source must be a URL or a ledger ID (S-...)")
    if sources is not None and re.fullmatch(r"S-[A-Z0-9\-]+", s) and s not in sources: e.append(f"unknown source ledger ID {s}")
    if checks is not None and r.get("check") and r["check"] not in checks: e.append(f"unknown kb check {r['check']}")
    if t == "http_header":
        if r.get("expect") not in ("present", "absent", "equals", "regex", "not_regex"): e.append("expect must be present|absent|equals|regex|not_regex")
        if r.get("expect") in ("equals", "regex", "not_regex") and not r.get("value"): e.append("value required for this expect")
        if r.get("expect") in ("regex", "not_regex") and r.get("value"):
            try: re.compile(r["value"])
            except re.error: e.append("value is not a valid regex")
    if t == "path_probe":
        if not str(r.get("path", "")).startswith("/"): e.append("path must start with /")
        if r.get("expect_status") and not all(isinstance(x, int) for x in r["expect_status"]): e.append("expect_status must be a list of integers")
        if r.get("finding_when", "found") not in ("found", "missing"): e.append("finding_when must be found|missing")
        for k in ("body_regex", "not_body_regex"):
            if r.get(k):
                try: re.compile(r[k])
                except re.error: e.append(f"{k} is not a valid regex")
    if t == "banner_version":
        try: re.compile(r.get("regex", ""))
        except re.error: e.append("regex is not valid")
        if not (r.get("bad_below") or r.get("bad_versions")): e.append("need bad_below or bad_versions")
    if t == "dns_record":
        if r.get("expect") not in ("present", "absent", "regex", "not_regex"): e.append("expect must be present|absent|regex|not_regex")
        if r.get("expect") in ("regex", "not_regex") and not r.get("value"): e.append("value required")
    return e

def load_packs(extra_dirs=(), include_pending=False, root=ROOT):
    """(rules, problems). Only approved rules are returned unless include_pending is set."""
    rules, probs, seen = [], [], {}
    src, chk = source_ids(root), load_checks(root)
    dirs = [os.path.join(root, "data", "packs")] + list(extra_dirs) + ([os.path.join(root, "data", "incoming")] if include_pending else [])
    for d in dirs:
        for f in sorted(glob.glob(os.path.join(d, "*.json"))):
            try: pack = json.loads(_read(f))
            except json.JSONDecodeError as ex: probs.append((f, "-", [f"invalid JSON: {ex}"])); continue
            for r in pack.get("rules", []):
                errs = validate_rule(r, src, chk)
                if r.get("id") in seen: errs.append(f"duplicate id (also in {seen[r['id']]})")
                seen[r.get("id")] = os.path.basename(f)
                if errs: probs.append((f, r.get("id", "?"), errs)); continue
                r = dict(r); r["_pack"] = os.path.basename(f)
                if r["status"] == "approved" or include_pending: rules.append(r)
    return rules, probs

def pack_hash(rules):
    return hashlib.sha256(json.dumps(sorted(r["id"] + "|" + json.dumps({k: v for k, v in r.items() if k != "_pack"}, sort_keys=True) for r in rules)).encode()).hexdigest()[:12]
