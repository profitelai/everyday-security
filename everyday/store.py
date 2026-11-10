"""SQLite history of runs, and diffs between runs. File: reports/history.db"""
import json, os, sqlite3, time
from . import registry

DB = os.path.join(registry.ROOT, "reports", "history.db")

def conn(path=DB):
    os.makedirs(os.path.dirname(path), exist_ok=True); c = sqlite3.connect(path)
    c.executescript("""CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, started TEXT, finished TEXT, version TEXT, pack_hash TEXT, sites INT, deep INT);
    CREATE TABLE IF NOT EXISTS results(run_id TEXT, host TEXT, check_id TEXT, status TEXT, severity TEXT, pillar TEXT, title TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS site_scores(run_id TEXT, host TEXT, score INT, grade TEXT);
    CREATE INDEX IF NOT EXISTS r1 ON results(run_id, host);""")
    cols = {r[1] for r in c.execute("PRAGMA table_info(results)")}          # older databases gain the evidence columns in place
    for col in ("evidence", "confidence"):
        if col not in cols: c.execute(f"ALTER TABLE results ADD COLUMN {col} TEXT")
    return c

def save(run, run_id, path=DB):
    c = conn(path)
    c.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?)", (run_id, run["started"], run["finished"], run["version"], run["pack_hash"], len(run["sites"]), int(run["deep"])))
    c.execute("DELETE FROM results WHERE run_id=?", (run_id,)); c.execute("DELETE FROM site_scores WHERE run_id=?", (run_id,))
    for s in run["sites"]:
        c.execute("INSERT INTO site_scores VALUES (?,?,?,?)", (run_id, s["host"], s["score"], s["grade"]))
        c.executemany("INSERT INTO results (run_id, host, check_id, status, severity, pillar, title, detail, evidence, confidence) VALUES (?,?,?,?,?,?,?,?,?,?)", [(run_id, s["host"], r["id"], r["status"], r["severity"], r.get("pillar", ""), r.get("title", ""), r["detail"], json.dumps(r["evidence"]) if r.get("evidence") is not None else None, r.get("confidence")) for r in s["results"]])
    c.commit(); c.close()

def previous_run(run_id, path=DB):
    c = conn(path); r = c.execute("SELECT id FROM runs WHERE id < ? ORDER BY id DESC LIMIT 1", (run_id,)).fetchone(); c.close(); return r[0] if r else None

def issues(run_id, path=DB):
    c = conn(path); rows = c.execute("SELECT host, check_id, status, severity, title, detail FROM results WHERE run_id=? AND status IN ('FAIL','WARN')", (run_id,)).fetchall(); c.close()
    return {(h, i): {"host": h, "id": i, "status": s, "severity": sv, "title": t, "detail": d} for h, i, s, sv, t, d in rows}

def diff(run_id, prev_id, path=DB):
    """New and resolved FAIL/WARN findings between two runs (only hosts scanned in both)."""
    if not prev_id: return None
    c = conn(path); hosts_now = {r[0] for r in c.execute("SELECT host FROM site_scores WHERE run_id=?", (run_id,))}; hosts_prev = {r[0] for r in c.execute("SELECT host FROM site_scores WHERE run_id=?", (prev_id,))}; c.close()
    common = hosts_now & hosts_prev; a, b = issues(prev_id, path), issues(run_id, path)
    new = [v for k, v in b.items() if k not in a and k[0] in common]; gone = [v for k, v in a.items() if k not in b and k[0] in common]
    return {"previous": prev_id, "new": sorted(new, key=lambda x: (x["host"], x["id"])), "resolved": sorted(gone, key=lambda x: (x["host"], x["id"]))}

def runs(limit=30, path=DB):
    c = conn(path); r = c.execute("SELECT id, started, sites, deep, pack_hash FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall(); c.close(); return r
