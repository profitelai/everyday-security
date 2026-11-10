#!/usr/bin/env python3
"""Compare our kb/ against reference folders (third-party material we must not copy). 
For every check, report the share of its word 6-grams that also occur anywhere in the references.
A high score is a reason for human review, not a legal finding; a low score is not proof of independence.
usage: similarity.py REF_DIR [REF_DIR ...] [--max 0.10]"""
import os, re, sys
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
N = 6
def words(t): return re.findall(r"[a-z0-9]+", t.lower())
def grams(t):
    w = words(t); return {" ".join(w[i:i + N]) for i in range(len(w) - N + 1)}
args = [a for a in sys.argv[1:] if not a.startswith("--")]
mx = float(sys.argv[sys.argv.index("--max") + 1]) if "--max" in sys.argv else 0.10
if "--max" in sys.argv: args = [a for a in args if a != sys.argv[sys.argv.index("--max") + 1]]
ref = set(); nfiles = 0
for r in args:
    for dp, _, fn in os.walk(os.path.expanduser(r)):
        for f in fn:
            if os.path.splitext(f)[1].lower() in (".md", ".txt", ".json", ".py", ".sh", ".yml", ".yaml"):
                try: ref |= grams(open(os.path.join(dp, f), errors="ignore").read()); nfiles += 1
                except OSError: pass
print(f"reference: {nfiles} files, {len(ref):,} distinct {N}-grams\n")
bad = 0; rows = []
for dp, _, fn in os.walk(os.path.join(ROOT, "kb")):
    for f in sorted(fn):
        if not f.endswith(".md"): continue
        t = open(os.path.join(dp, f)).read(); t = re.sub(r"^---\n.*?\n---\n", "", t, flags=re.S)
        t = re.sub(r"```.*?```", "", t, flags=re.S)   # command lines are factual and overlap by necessity; prose is what we compare
        g = grams(t); s = len(g & ref) / max(1, len(g)); rows.append((s, f[:-3], len(g & ref), len(g)))
for s, i, a, b in sorted(rows, reverse=True):
    flag = "REVIEW" if s > mx else "ok"; bad += s > mx
    print(f"{i:9} {s*100:5.1f}%  ({a}/{b} 6-grams)  {flag}")
print(f"\n{bad} of {len(rows)} above {mx*100:.0f}%")
sys.exit(1 if bad else 0)
