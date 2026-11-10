#!/usr/bin/env python3
"""Profitell Security Consulting - Everyday Security Workbench: a localhost-only browser/editor for the knowledge-base "brains" on this machine.
Lists every brain with its author, license, pillars, notes and copyright wording; compares a copy with its original
(provenance); edits files only inside workspace/ (originals stay read-only); every save is backed up first.
Standard library only.   python3 server.py   ->   http://127.0.0.1:5090"""
import os, re, json, hashlib, secrets, shutil, time, difflib, socket, subprocess, sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

H = os.path.expanduser("~"); HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "5090"))
WS, BK, IMP = (os.path.join(HERE, d) for d in ("workspace", "backups", "imports"))
TOKEN = secrets.token_urlsafe(24)
SCAN = [p for p in os.environ.get("WORKBENCH_SCAN", "").split(":") if p] + [IMP, WS]   # folders to inventory (colon-separated), set WORKBENCH_SCAN
EDITABLE = [WS] + [p for p in os.environ.get("WORKBENCH_EDITABLE", "").split(":") if p]   # only the workspace is ever writable
UPSTREAM_SEC = os.environ.get("WORKBENCH_BASELINE", "")   # folder holding the original as provided; copies named like it are compared to it
SKIP = {".git", "node_modules", "__pycache__", ".DS_Store"}
TEXT = {".md", ".py", ".json", ".sh", ".toml", ".yml", ".yaml", ".txt", ".html", ".js", ".mjs", ".css", ".svg", ".canvas", ".base", ".csv", ".cfg", ".ini"}
PAT = re.compile(os.environ.get("WORKBENCH_EXTRA_PATTERN", "(?!x)x") + r"|Copyright|\(c\) 20\d\d|Proprietary|Source-Available|All rights reserved|authorized collaborators|paid customers", re.I)

def rid(p): return os.path.relpath(p, H)
def abspath(i): return os.path.normpath(os.path.join(H, i))
def is_text(p): return os.path.splitext(p)[1].lower() in TEXT
def looks_like_brain(d): return any(os.path.exists(os.path.join(d, m)) for m in ("wiki", "kb", "CODEX.md", "SKILL.md", ".claude-plugin", "pyproject.toml"))

def discover():
    found = {}
    def walk(d, depth):
        try: kids = sorted(os.listdir(d))
        except OSError: return
        for k in kids:
            p = os.path.join(d, k)
            if k.startswith(".") or k in SKIP or not os.path.isdir(p): continue
            if looks_like_brain(p): found[rid(os.path.realpath(p) if False else p)] = p
            elif depth < 2: walk(p, depth + 1)
    for r in SCAN:
        if os.path.isdir(r): walk(r, 0)
    for r in [p for p in os.environ.get("WORKBENCH_BRAINS", "").split(":") if p]:   # explicit brain folders
        if os.path.isdir(r): found[rid(r)] = r
    return found

def files_of(root):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP]
        for f in fn:
            if f in SKIP: continue
            p = os.path.join(dp, f); out.append(os.path.relpath(p, root))
    return sorted(out)

def read_lines(p, minlen=0):
    try:
        if os.path.getsize(p) > 2_000_000: return None
        return [l.strip() for l in open(p, encoding="utf-8").read().splitlines() if len(l.strip()) >= max(minlen, 1)]
    except Exception: return None

def meta(root):
    ver = lic = auth = ""
    pj = os.path.join(root, "pyproject.toml")
    if os.path.exists(pj):
        t = open(pj, errors="ignore").read()
        m = re.search(r'^version\s*=\s*"([^"]+)"', t, re.M); ver = m.group(1) if m else ""
        m = re.search(r'authors\s*=\s*\[\{\s*name\s*=\s*"([^"]+)"', t); auth = m.group(1) if m else ""
        m = re.search(r'license\s*=\s*\{?\s*(?:text\s*=\s*)?"([^"]+)"', t); lic = m.group(1) if m else ""
    pl = os.path.join(root, ".claude-plugin", "plugin.json")
    if os.path.exists(pl):
        try:
            j = json.load(open(pl)); ver = ver or j.get("version", ""); lic = lic or j.get("license", "")
            a = j.get("author"); auth = auth or (a.get("name") if isinstance(a, dict) else a or "")
        except Exception: pass
    for f in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
        fp = os.path.join(root, f)
        if os.path.exists(fp):
            first = open(fp, errors="ignore").readline().strip().lstrip("# ")[:80]
            lic = first or lic; break
    if not ver:
        cl = os.path.join(root, "CHANGELOG.md")
        if os.path.exists(cl):
            m = re.search(r"^##\s*\[?v?(\d+\.\d+[\w.\-]*)", open(cl, errors="ignore").read(), re.M); ver = m.group(1) if m else ""
    return ver, lic, auth

def lic_class(lic):
    l = lic.lower()
    if re.search(r"\bmit\b|apache|bsd|isc|cc0", l): return "open"
    if re.search(r"proprietary|source-available|commercial|custom", l): return "restricted"
    return "unknown" if not l else "other"

def pillars(root):
    w = os.path.join(root, "wiki"); out = {}
    if not os.path.isdir(w): w = os.path.join(root, "kb")
    if not os.path.isdir(w): return out
    for dp, dn, fn in os.walk(w):
        dn[:] = [d for d in dn if d not in SKIP and not d.startswith(".")]
        parts = os.path.relpath(dp, w).split(os.sep)
        if parts == ["."]: continue
        key = "/".join(parts[:2]) if parts[0] == "concepts" and len(parts) > 1 else parts[0]
        n = sum(1 for f in fn if f.endswith(".md") and not f.startswith("_"))
        if n: out[key] = out.get(key, 0) + n
    return dict(sorted(out.items()))

def hits_of(root):
    res = []
    for rel in files_of(root):
        if not is_text(rel): continue
        p = os.path.join(root, rel)
        try:
            if os.path.getsize(p) > 2_000_000: continue
            for i, l in enumerate(open(p, encoding="utf-8").read().splitlines(), 1):
                if PAT.search(l): res.append({"file": rel, "line": i, "text": l.strip()[:220]})
        except Exception: pass
    return res

def baseline_of(i):
    """Folder holding the 'original as provided' for brain id i (or None). """
    if not UPSTREAM_SEC or i == rid(UPSTREAM_SEC): return None
    root = abspath(i); o = os.path.join(root, ".origin")
    src = open(o).read().strip() if os.path.exists(o) else i
    if src == rid(UPSTREAM_SEC): return None
    if os.path.basename(UPSTREAM_SEC).lower() in src.lower(): return UPSTREAM_SEC
    return None

def provenance(root, base):
    B = {f for f in files_of(base)}; rows = []; tot = his = 0
    for rel in files_of(root):
        p = os.path.join(root, rel)
        if rel not in B: cls = "new"
        elif hashlib.sha1(open(p, "rb").read()).digest() == hashlib.sha1(open(os.path.join(base, rel), "rb").read()).digest(): cls = "identical"
        else: cls = "modified"
        rows.append((rel, cls))
    cls_of = dict(rows)
    for rel, c in rows:
        if not is_text(rel): continue
        nl = read_lines(os.path.join(root, rel), 40)
        if not nl: continue
        tot += len(nl)
        if c == "identical": his += len(nl)
        elif c == "modified":
            bl = set(read_lines(os.path.join(base, rel), 40) or []); his += sum(1 for l in nl if l in bl)
    counts = {}
    for _, c in rows: counts[c] = counts.get(c, 0) + 1
    removed = len([f for f in B if f not in cls_of])
    return cls_of, {"identical": counts.get("identical", 0), "modified": counts.get("modified", 0), "new": counts.get("new", 0), "removed": removed,
                    "substantive_lines": tot, "share_from_original": round(100 * his / tot, 1) if tot else 0}

CACHE = {}
CFILE = os.path.join(HERE, ".cache.json")
try: DISK = json.load(open(CFILE))
except Exception: DISK = {}
def sig(root):
    n = sz = mt = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP]
        for f in fn:
            try: st = os.stat(os.path.join(dp, f)); n += 1; sz += st.st_size; mt = max(mt, int(st.st_mtime))
            except OSError: pass
    return f"{n}:{sz}:{mt}"
def info(i, refresh=False):
    if i in CACHE and not refresh: return CACHE[i]
    b0 = baseline_of(i); key = sig(abspath(i)) + "|" + (sig(b0) if b0 and os.path.isdir(b0) else "")
    if not refresh and i in DISK and DISK[i].get("sig") == key: CACHE[i] = DISK[i]["info"]; return CACHE[i]
    root = abspath(i); ver, lic, auth = meta(root); fl = files_of(root)
    b = baseline_of(i)
    d = {"id": i, "name": os.path.basename(root), "path": root, "kind": "vault brain" if (os.path.isdir(os.path.join(root, "wiki")) or os.path.isdir(os.path.join(root, "kb"))) else "skill / plugin",
         "version": ver, "license": lic, "license_class": lic_class(lic), "author": auth, "files": len(fl), "notes": sum(1 for f in fl if f.endswith(".md")),
         "pillars": pillars(root), "copyright_hits": len(hits_of(root)), "editable": any(root == e or root.startswith(e + os.sep) for e in EDITABLE),
         "baseline": rid(b) if b else None, "is_baseline": bool(UPSTREAM_SEC) and i == rid(UPSTREAM_SEC)}
    if b and os.path.isdir(b):
        _, summ = provenance(root, b); d["provenance"] = summ; d["baseline_pillars"] = pillars(b); d["baseline_version"] = meta(b)[0]
    CACHE[i] = d; DISK[i] = {"sig": key, "info": d}
    try: json.dump(DISK, open(CFILE, "w"))
    except OSError: pass
    return d

def kb_root():
    for r in [p for p in os.environ.get("WORKBENCH_BRAINS", "").split(":") if p]:
        if os.path.isdir(os.path.join(r, "kb")): return r
    return None

def parse_kb(root):
    out = []
    for dp, dn, fn in os.walk(os.path.join(root, "kb")):
        for f in sorted(fn):
            if not f.endswith(".md"): continue
            t = open(os.path.join(dp, f), encoding="utf-8").read(); m = re.match(r"---\n(.*?)\n---\n(.*)", t, re.S)
            if not m: continue
            fm = {}
            for l in m.group(1).splitlines():
                if ": " in l:
                    k, v = l.split(": ", 1); v = v.strip()
                    fm[k] = [x.strip() for x in v[1:-1].split(",")] if v.startswith("[") else v.strip('"')
            fm["body"] = m.group(2); fm["path"] = os.path.relpath(os.path.join(dp, f), root); out.append(fm)
    return out

def safe_host(h):
    import ipaddress
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", h or "") or "." not in h: raise ValueError("enter a host name such as example.com")
    for a in socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(a[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved: raise ValueError("private and local addresses are not allowed")
    return h

def safe(i, rel):
    root = abspath(i); p = os.path.normpath(os.path.join(root, rel))
    if not (p == root or p.startswith(root + os.sep)): raise ValueError("path outside brain")
    return root, p

def fork(src_id, name):
    name = re.sub(r"[^a-zA-Z0-9._-]", "-", name).strip("-") or "fork"
    dst = os.path.join(WS, name)
    if os.path.exists(dst): raise ValueError("workspace already has " + name)
    shutil.copytree(abspath(src_id), dst, ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__"))
    open(os.path.join(dst, ".origin"), "w").write(src_id); CACHE.pop(rid(dst), None); return rid(dst)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8"); self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"); self.end_headers(); self.wfile.write(b)
    def _host_ok(self): return (self.headers.get("Host") or "").rsplit(":", 1)[0] in ("127.0.0.1", "localhost")   # blocks DNS-rebinding hostnames
    def do_GET(self):
        if not self._host_ok(): return self._send(403, {"error": "bad host"})
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path == "/": return self._send(200, open(os.path.join(HERE, "static", "index.html")).read().replace("__TOKEN__", TOKEN), "text/html")
            if u.path == "/api/brains":
                found = discover(); rows = [info(i, q.get("refresh") == "1") for i in sorted(rid(p) for p in found.values())]
                return self._send(200, {"brains": rows})
            if u.path == "/api/files":
                i = q["id"]; root = abspath(i); b = baseline_of(i); cls = {}
                if b and os.path.isdir(b): cls, _ = provenance(root, b)
                hits = {}
                for h in hits_of(root): hits[h["file"]] = hits.get(h["file"], 0) + 1
                out = [{"path": f, "size": os.path.getsize(os.path.join(root, f)), "text": is_text(f), "class": cls.get(f, ""), "hits": hits.get(f, 0)} for f in files_of(root)]
                return self._send(200, {"files": out})
            if u.path == "/api/kb":
                r = kb_root()
                if not r: return self._send(200, {"checks": []})
                return self._send(200, {"checks": parse_kb(r), "pillars_planned": ["incident-response", "cloud-and-saas-accounts", "wordpress-and-cms", "containers", "vendor-and-supply-chain"]})
            if u.path == "/api/engine":
                r = kb_root()
                if not r: return self._send(200, {})
                p = subprocess.run([sys.executable, "-m", "everyday", "stats"], capture_output=True, text=True, cwd=r, env={**os.environ, "PYTHONPATH": r}, timeout=60)
                runs = []
                rd = os.path.join(r, "reports", "runs")
                for rid in sorted(os.listdir(rd), reverse=True)[:30] if os.path.isdir(rd) else []:
                    try: j = json.load(open(os.path.join(rd, rid, "results.json"))); runs.append({"id": rid, "sites": [{"host": x["host"], "grade": x["grade"], "score": x["score"], "fail": x["tally"].get("FAIL", 0), "warn": x["tally"].get("WARN", 0)} for x in j["sites"]], "deep": j["deep"], "rules": j.get("rules_loaded")})
                    except Exception: pass
                return self._send(200, {"stats": json.loads(p.stdout or "{}"), "runs": runs})
            if u.path == "/report":
                r = kb_root(); rid = q.get("run", "")
                if not r or not re.fullmatch(r"\d{8}-\d{6}", rid): return self._send(400, {"error": "bad run id"})
                f = os.path.join(r, "reports", "runs", rid, "report.html")
                if not os.path.exists(f): return self._send(404, {"error": "no such report"})
                b = open(f, "rb").read(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(b))); self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"); self.end_headers(); self.wfile.write(b); return
            if u.path == "/api/copyright": return self._send(200, {"hits": hits_of(abspath(q["id"]))})
            if u.path == "/api/file":
                _, p = safe(q["id"], q["path"])
                if not is_text(p): return self._send(415, {"error": "not a text file"})
                if os.path.getsize(p) > 2_000_000: return self._send(413, {"error": "file too large"})
                return self._send(200, {"content": open(p, encoding="utf-8").read()})
            if u.path == "/api/original":
                i = q["id"]; b = baseline_of(i); _, p = safe(i, q["path"])
                bp = os.path.join(b, q["path"]) if b else None
                if not bp or not os.path.exists(bp): return self._send(200, {"content": None})
                return self._send(200, {"content": open(bp, encoding="utf-8").read()})
            if u.path == "/api/export":
                import csv, io
                hs = hits_of(abspath(q["id"])); buf = io.StringIO(); w = csv.writer(buf); w.writerow(["file", "line", "text"])
                for h in hs: w.writerow([h["file"], h["line"], h["text"]])
                return self._send(200, buf.getvalue(), "text/csv")
            if u.path == "/api/diff":
                i = q["id"]; b = baseline_of(i); _, p = safe(i, q["path"])
                if not b: return self._send(200, {"diff": "(no original to compare with)"})
                bp = os.path.join(b, q["path"])
                if not os.path.exists(bp): return self._send(200, {"diff": "(file is new: not in the original)"})
                a = open(bp, encoding="utf-8").read().splitlines(); c = open(p, encoding="utf-8").read().splitlines()
                return self._send(200, {"diff": "\n".join(difflib.unified_diff(a, c, "original", "this copy", lineterm="", n=2)) or "(identical to the original)"})
            return self._send(404, {"error": "not found"})
        except KeyError as e: return self._send(400, {"error": f"missing {e}"})
        except (ValueError, OSError, UnicodeDecodeError) as e: return self._send(400, {"error": str(e)})
    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-Token") != TOKEN: return self._send(403, {"error": "forbidden"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}"); u = urlparse(self.path)
            if u.path == "/api/fork":
                new = fork(body["id"], body["name"]); return self._send(200, {"id": new})
            if u.path == "/api/check":
                if not body.get("consent"): return self._send(400, {"error": "confirm that you own the site or may test it"})
                host = safe_host(body.get("host", "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0])
                r = kb_root(); script = os.path.join(r, "tools", "check", "everyday_check.py")
                p = subprocess.run([sys.executable, "-I", script, host, "--json"], capture_output=True, text=True, timeout=120)
                return self._send(200, json.loads(p.stdout))
            if u.path == "/api/save":
                root, p = safe(body["id"], body["path"])
                if not any(root == e or root.startswith(e + os.sep) for e in EDITABLE): return self._send(403, {"error": "read-only original: fork it to the workspace first"})
                if not is_text(p) or len(body["content"]) > 2_000_000: return self._send(400, {"error": "not editable"})
                if os.path.exists(p):
                    bdir = os.path.join(BK, body["id"].replace(os.sep, "__")); os.makedirs(bdir, exist_ok=True)
                    shutil.copy2(p, os.path.join(bdir, body["path"].replace(os.sep, "__") + "." + time.strftime("%Y%m%d_%H%M%S")))
                os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w", encoding="utf-8").write(body["content"]); CACHE.pop(body["id"], None)
                return self._send(200, {"saved": True})
            return self._send(404, {"error": "not found"})
        except (KeyError, ValueError, OSError, json.JSONDecodeError) as e: return self._send(400, {"error": str(e)})

if __name__ == "__main__":
    print(f"Profitell Security Consulting Brain Workbench: http://127.0.0.1:{PORT}  (localhost only; originals read-only; edits only in {WS})")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
