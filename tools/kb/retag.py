#!/usr/bin/env python3
"""Normalize check tags to the controlled vocabulary in data/tags.json. Dry run by default; --apply rewrites the files.
Keeps 2 to 5 tags per check, most specific first; falls back to the pillar's area tag when fewer than 2 survive."""
import json, os, re, sys
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
V = json.load(open(os.path.join(ROOT, "data", "tags.json")))
AREA = {"tls": "tls", "http-headers": "headers", "mail-authentication": "mail", "web-app": "web", "server-hardening": "server", "dns": "dns", "backups-and-recovery": "backup", "privacy-compliance": "privacy", "incident-response": "incident-response", "cloud-and-saas-accounts": "cloud", "wordpress-and-cms": "cms", "containers": "containers", "vendor-and-supply-chain": "supply-chain"}
GENERIC = {"web", "server", "dns", "mail", "tls", "backup", "privacy", "domain", "network", "database", "cloud"}  # area tags rank after specific ones

def normalize(tags, pillar):
    out = []
    for t in tags:
        c = V["aliases"].get(t, t)
        if c in V["tags"] and c not in out: out.append(c)
    specific = [t for t in out if t not in GENERIC]; generic = [t for t in out if t in GENERIC]
    res = (specific + generic)[:5]
    a = AREA.get(pillar)
    if a and a not in res and len(res) < 5 and (not generic or len(res) < 2): res.append(a)
    if len(res) < 2 and a and a not in res: res.append(a)
    return res

if __name__ == "__main__":
    apply = "--apply" in sys.argv; n = 0
    for dp, _, fn in os.walk(os.path.join(ROOT, "kb")):
        for f in sorted(fn):
            if not f.endswith(".md") or f == "INDEX.md": continue
            p = os.path.join(dp, f); t = open(p, encoding="utf-8").read()
            m = re.search(r"^tags: \[(.*?)\]$", t, re.M); pm = re.search(r"^pillar: (\S+)$", t, re.M)
            if not m: continue
            old = [x.strip() for x in m.group(1).split(",") if x.strip()]; new = normalize(old, pm.group(1))
            if old != new:
                n += 1
                if apply: open(p, "w", encoding="utf-8").write(t.replace(m.group(0), f"tags: [{', '.join(new)}]", 1))
                else: print(f[:-3], old, "->", new)
    print(("rewrote" if apply else "would rewrite"), n, "files")
