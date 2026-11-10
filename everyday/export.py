"""The two ways to take a result out of Everyday Security.

1. PDF   : a printable report for a developer, a manager or a client (see pdf.py and report.to_html(pdf=True)).
2. JSON  : a "fix pack" the owner can hand to an AI assistant such as Claude to get step-by-step fix instructions.

Nothing here uploads anything. Both files are written to the run folder on this machine; the owner decides where they go."""
import datetime as dt, json, os, re
from . import HOME, REPO, VERSION

SCHEMA = "everyday-security/fix-pack/1"
SEV = ["critical", "high", "medium", "low", "info"]
STATUS_ORDER = {"FAIL": 0, "WARN": 1, "INCONCLUSIVE": 2, "MANUAL": 3}
SECTIONS = {"why it matters": "why_it_matters", "how to test": "how_to_test", "pass criteria": "pass_criteria", "fix": "fix", "risk and rollback": "risk_and_rollback"}
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

INSTRUCTIONS = [
    "You are helping the owner of the systems named below fix security findings reported by Everyday Security (Alpha). Work with the owner, one finding at a time, starting with the highest priority.",
    "A finding can be wrong. Before suggesting a change, tell the owner how to confirm it (see how_to_test) and compare with pass_criteria. If the evidence does not support the finding, say so.",
    "Findings with status INCONCLUSIVE or MANUAL are not failures: they mean the scanner could not judge them. Ask the owner to check by hand.",
    "For each finding give: what is wrong in plain words, the exact steps to fix it for the owner's setup (ask which web server, hosting, mail or DNS provider they use if the file does not say), how to verify the fix, and how to undo it (risk_and_rollback).",
    "Never run changes yourself unless the owner asked you to. Ask before anything that could interrupt a live service, and recommend a backup first.",
    "Only act on the hosts listed in this file. Do not scan or probe other systems. Do not ask the owner to paste passwords, keys or tokens.",
    "This is not legal, privacy or compliance advice. Items about privacy law are informational; suggest a qualified adviser for those.",
]


def sections(md):
    """Split a check page into its '## Heading' sections."""
    out = {}
    for m in re.finditer(r"^## (.+?)\n(.*?)(?=^## |\Z)", md, re.S | re.M):
        key = SECTIONS.get(m.group(1).strip().lower())
        if key: out[key] = m.group(2).strip()
    return out


def kb_sections(rel, root=ROOT):
    if not rel: return {}
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as f: return sections(f.read())
    except OSError: return {}


def priority(r):
    return (STATUS_ORDER.get(r["status"], 9), SEV.index(r["severity"]) if r["severity"] in SEV else 9, r["id"])


def fix_pack(run, run_id, root=ROOT, include_manual=True):
    """Build the JSON handed to an assistant. Only findings that need attention are included; passes are counted, not listed."""
    wanted = ("FAIL", "WARN", "INCONCLUSIVE") + (("MANUAL",) if include_manual else ())
    sites = []
    for s in run["sites"]:
        items = []
        for n, r in enumerate(sorted((r for r in s["results"] if r["status"] in wanted), key=priority), 1):
            f = {"priority": n, "id": r["id"], "title": r["title"], "status": r["status"], "severity": r["severity"], "pillar": r.get("pillar", ""),
                 "what_was_found": r["detail"], "confidence": r.get("confidence"), "evidence": r.get("evidence")}
            f.update(kb_sections(r.get("kb"), root))
            if r.get("kb"): f["reference"] = f"{REPO}/blob/main/{r['kb']}"
            items.append(f)
        sites.append({"host": s["host"], "name": s.get("name", s["host"]), "grade": s["grade"], "score": s["score"], "tally": s["tally"], "findings": items})
    return {"schema": SCHEMA, "tool": {"name": "Everyday Security", "version": VERSION, "maturity": "alpha", "by": "Profitell Security Consulting", "url": HOME},
            "run": {"id": run_id, "started": run.get("started"), "deep_scan": bool(run.get("deep")), "rules_loaded": run.get("rules_loaded")},
            "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "instructions_for_assistant": INSTRUCTIONS,
            "how_to_use": "Attach this file to a conversation with an AI assistant and say: Fix these findings with me, one at a time, and ask before each change.",
            "privacy_note": "This file lists weaknesses of the hosts named in it. Share it only with people and services you trust.",
            "sites": sites}


def write_fix_pack(run, run_id, folder, root=ROOT):
    path = os.path.join(folder, "fix-pack.json")
    with open(path, "w", encoding="utf-8") as f: json.dump(fix_pack(run, run_id, root), f, indent=1, ensure_ascii=False)
    return path
