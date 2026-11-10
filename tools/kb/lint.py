#!/usr/bin/env python3
"""Lint the knowledge base: required fields, known source IDs, required sections, unique IDs. Exit 1 on any problem."""
import os, re, sys
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
REQ = ["id", "title", "pillar", "severity", "standards", "sources", "tags", "target", "method", "tool", "automated", "status", "reviewed", "author"]
SECTIONS = ["## Why it matters", "## How to test", "## Pass criteria", "## Fix", "## Risk and rollback"]
SEV = {"critical", "high", "medium", "low", "info"}
LEDGERS = [os.path.join(ROOT, "docs", "sources.md")] + sorted(os.path.join(ROOT, "docs", "sources.d", f) for f in os.listdir(os.path.join(ROOT, "docs", "sources.d")) if f.endswith(".md"))
src_ids = set(i for l in LEDGERS for i in re.findall(r"^\| (S-[A-Z0-9\-]+) \|", open(l).read(), re.M))
import json
VOCAB = set(json.load(open(os.path.join(ROOT, "data", "tags.json")))["tags"])
errs, seen, n = [], {}, 0
for dp, _, fn in os.walk(os.path.join(ROOT, "kb")):
    for f in sorted(fn):
        if not f.endswith(".md") or f == "INDEX.md": continue
        p = os.path.join(dp, f); t = open(p).read(); n += 1
        m = re.match(r"---\n(.*?)\n---\n", t, re.S)
        if not m: errs.append(f"{p}: no front matter"); continue
        fm = dict(l.split(": ", 1) for l in m.group(1).splitlines() if ": " in l)
        for k in REQ:
            if k not in fm: errs.append(f"{p}: missing {k}")
        if fm.get("severity") not in SEV: errs.append(f"{p}: bad severity")
        if fm.get("id") != f[:-3]: errs.append(f"{p}: id does not match file name")
        if fm.get("id") in seen: errs.append(f"{p}: duplicate id (also {seen[fm['id']]})")
        seen[fm.get("id")] = p
        for s in re.findall(r"S-[A-Z0-9\-]+", fm.get("sources", "")):
            if s not in src_ids: errs.append(f"{p}: unknown source {s}")
        if not re.findall(r"S-[A-Z0-9\-]+", fm.get("sources", "")): errs.append(f"{p}: no sources")
        tg = [x.strip() for x in re.sub(r"[\[\]]", "", fm.get("tags", "")).split(",") if x.strip()]
        if not 2 <= len(tg) <= 5: errs.append(f"{p}: needs 2 to 5 tags, has {len(tg)}")
        for x in tg:
            if x not in VOCAB: errs.append(f"{p}: tag '{x}' is not in data/tags.json")
        for s in SECTIONS:
            if s not in t: errs.append(f"{p}: missing section {s}")
print(f"{n} checks, {len(src_ids)} sources, {len(errs)} problems")
for e in errs: print(" -", e)
sys.exit(1 if errs else 0)
