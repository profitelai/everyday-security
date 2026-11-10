"""Shared vocabulary: statuses, severities, scoring."""
STATUSES = ("FAIL", "WARN", "MANUAL", "PASS", "INFO")
SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

def status_for_hit(severity):
    """Status a data-pack rule produces when it matches (a finding)."""
    return {"critical": "FAIL", "high": "FAIL", "medium": "WARN", "low": "WARN", "info": "INFO"}.get(severity, "WARN")

def score(results):
    """0-100, higher is better. Each failed check costs twice its severity weight, each warning one weight. Checks that
    cannot be judged from outside (MANUAL), passes and notes cost nothing. A comparison aid, not a certification."""
    pen = 0.0
    for r in results:
        w = SEV_WEIGHT.get(r.get("severity", "low"), 1)
        pen += {"FAIL": 2 * w, "WARN": w}.get(r["status"], 0)
    s = max(0, round(100 - pen)); g = "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"
    return s, g

def tally(results):
    t = {k: 0 for k in STATUSES}
    for r in results: t[r["status"]] = t.get(r["status"], 0) + 1
    return t
