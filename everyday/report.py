"""Reports from a fleet run: self-contained HTML, Markdown and CSV."""
import csv, html, io, json, os, urllib.parse
from . import HOME, REPO, VERSION
from .model import SEV_ORDER, tally

COLORS = {"FAIL": "#d1242f", "WARN": "#bf8700", "INCONCLUSIVE": "#8250df", "PASS": "#1a7f37", "MANUAL": "#6e7781", "INFO": "#0969da"}
E = html.escape
try:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "profitell-logo.svg"), encoding="utf-8") as _f: LOGO = _f.read().replace('width="34" height="34"', 'width="100%" height="100%"', 1)
except OSError: LOGO = ""

LOGO_URI = "data:image/svg+xml," + urllib.parse.quote(LOGO.replace('width="100%" height="100%"', 'width="26" height="26"', 1)) if LOGO else ""
FOOT_TEXT = f"  Profitell Security Consulting · profitell.com · Everyday Security {VERSION} (Alpha)"
PRINT_CSS = """
.brandbar{display:flex;align-items:center;gap:14px;padding-bottom:14px;border-bottom:2px solid var(--tx);margin-bottom:12px}.brandbar .logo{width:44px;height:44px;flex:none}.brandbar h1{font-size:24px;letter-spacing:-.3px}.brandbar .sub{color:var(--mut);font-size:13px}
.alpha{border:1px solid var(--line);border-left:4px solid #bf8700;background:var(--panel);padding:8px 12px;border-radius:6px;font-size:12px;margin:12px 0}
.foot{margin-top:34px;border-top:1px solid var(--line);padding-top:10px;display:flex;align-items:center;gap:10px;font-size:11px;color:var(--mut)}.foot .logo{width:26px;height:26px;flex:none}.foot b{color:var(--tx)}
.top ol{margin:6px 0 0 18px;padding:0}.top li{margin:3px 0}.mini td{font-size:11px;padding:3px 8px}
@page{size:A4;margin:16mm 13mm 22mm;@bottom-left{content:LOGOURL "FOOTTEXT";font:9px sans-serif;color:#57606a;vertical-align:middle;white-space:pre;padding-top:2mm;border-top:.5pt solid #d0d7de}@bottom-right{content:"Page " counter(page) " of " counter(pages);font:9px sans-serif;color:#57606a;vertical-align:middle;padding-top:2mm;border-top:.5pt solid #d0d7de}}
@media print{:root{--bg:#fff;--tx:#1f2328;--mut:#57606a;--line:#d0d7de;--panel:#f6f8fa}body{font-size:11.5px;-webkit-print-color-adjust:exact;print-color-adjust:exact}main{max-width:none;padding:0}
tr,.card,.alpha{break-inside:avoid}thead{display:table-header-group}h2{break-after:avoid}h2.site{break-before:page}details>summary{display:none}a{color:inherit;text-decoration:none}
.foot{display:none}pre{white-space:pre-wrap;font-size:10px;margin:4px 0}.cell{-webkit-print-color-adjust:exact}}
"""
PRINT_CSS = PRINT_CSS.replace("LOGOURL", 'url("' + LOGO_URI + '")' if LOGO_URI else '""').replace("FOOTTEXT", FOOT_TEXT)

def worst(results):
    for s in ("FAIL", "WARN", "INCONCLUSIVE", "PASS", "MANUAL", "INFO"):
        if any(r["status"] == s for r in results): return s
    return ""

def evidence_html(r, opened=False):
    """Recorded evidence behind a finding (what was asked, what came back), shown under the detail text."""
    ev = r.get("evidence")
    if ev is None: return ""
    conf = f"confidence: {E(str(r['confidence']))} · " if r.get("confidence") else ""
    return f"<details class='m'{' open' if opened else ''}><summary>{conf}evidence</summary><pre>{E(json.dumps(ev, indent=1, sort_keys=True, ensure_ascii=False))}</pre></details>"

def fleet_numbers(run):
    sites = run["sites"]; t = {"FAIL": 0, "WARN": 0, "INCONCLUSIVE": 0, "PASS": 0, "MANUAL": 0, "INFO": 0}
    for s in sites:
        for k, v in tally(s["results"]).items(): t[k] = t.get(k, 0) + v
    avg = round(sum(s["score"] for s in sites) / len(sites)) if sites else 0
    return t, avg

def to_html(run, run_id, diff=None, pdf=False):
    t, avg = fleet_numbers(run); sites = run["sites"]; pillars = sorted({r.get("pillar", "") for s in sites for r in s["results"] if r.get("pillar")})
    h = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Everyday Security report {E(run_id)}</title>
<style>:root{{--bg:#fff;--tx:#1f2328;--mut:#656d76;--line:#d0d7de;--panel:#f6f8fa}}@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--tx:#e6edf3;--mut:#8b949e;--line:#30363d;--panel:#161b22}}}}
body{{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,Segoe UI,sans-serif}}main{{max-width:1200px;margin:auto;padding:20px}}h1{{font-size:22px;margin:0}}h2{{font-size:16px;margin:26px 0 8px}}
a{{color:#0969da}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}}th{{background:var(--panel);font-size:12px;color:var(--mut)}}
.cards{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:110px}}.card b{{font-size:24px;display:block}}
.pill{{display:inline-block;border-radius:99px;padding:0 8px;font-size:11px;color:#fff}}.g{{font-weight:700;font-size:18px}}.m{{color:var(--mut)}}.cell{{width:22px;height:22px;border-radius:4px;display:inline-block}}code{{font-size:12px}}details{{margin:8px 0}}summary{{cursor:pointer;font-weight:600}}
.tag{{border:1px solid var(--line);border-radius:99px;padding:0 7px;font-size:11px;color:var(--mut);margin-right:3px}}{PRINT_CSS}</style></head><body><main>
<div class="brandbar"><div class="logo">{LOGO}</div><div><h1>Everyday Security report</h1><div class="sub">Security check by Profitell Security Consulting · run {E(run_id)} · {E(run['started'][:10])}</div></div></div>
<div class="m">{E(run['started'][:19])} UTC · v{VERSION} · rules loaded {run['rules_loaded']} (pack {E(run['pack_hash'])}) · {'deep scan' if run['deep'] else 'standard scan'}</div>
<div class="cards"><div class="card"><b>{len(sites)}</b>sites</div><div class="card"><b>{avg}</b>average score</div><div class="card"><b style="color:{COLORS['FAIL']}">{t['FAIL']}</b>fail</div><div class="card"><b style="color:{COLORS['WARN']}">{t['WARN']}</b>warn</div><div class="card"><b style="color:{COLORS['PASS']}">{t['PASS']}</b>pass</div><div class="card"><b style="color:{COLORS['INCONCLUSIVE']}">{t['INCONCLUSIVE']}</b>inconclusive</div><div class="card"><b>{t['MANUAL']}</b>manual</div></div>
<p class="m">The score is a comparison aid (each failed check costs twice its severity weight, each warning one weight), not a certification. MANUAL items could not be judged from outside and INCONCLUSIVE items did not give enough evidence to judge; neither is scored.</p>
<div class="alpha"><b>Alpha (v{VERSION}).</b> The checks are drafts written from public sources and have not been reviewed by a named security professional or measured for accuracy. A finding can be wrong, and a clean result is not proof of safety. Use this report as a starting point and confirm each finding before changing anything.</div>
<h2>Sites</h2><table><thead><tr><th>Site</th><th>Tags</th><th>Grade</th><th>Score</th><th>Fail</th><th>Warn</th><th>Pass</th>""" + "".join(f"<th title='{E(p)}'>{E(p[:6])}</th>" for p in pillars) + "</tr></thead><tbody>"]
    for s in sites:
        tt = s["tally"]; h.append(f"<tr><td><a href='#{E(s['host'])}'><b>{E(s['name'])}</b></a><div class='m'>{E(s['host'])}</div></td><td>{''.join(f'<span class=tag>{E(x)}</span>' for x in s['tags'])}</td><td class='g'>{s['grade']}</td><td>{s['score']}</td><td>{tt.get('FAIL',0)}</td><td>{tt.get('WARN',0)}</td><td>{tt.get('PASS',0)}</td>")
        for p in pillars:
            w = worst([r for r in s["results"] if r.get("pillar") == p]); h.append(f"<td>{'<span class=cell title=%s style=background:%s></span>' % (repr(p + ': ' + w), COLORS[w]) if w else ''}</td>")
        h.append("</tr>")
    h.append("</tbody></table><p class='m'>Cell colour = worst result in that pillar for that site (red fail, amber warn, green pass, grey manual).</p>")
    if diff:
        h.append(f"<h2>Changes since run {E(diff['previous'])}</h2>")
        for k, lab in (("new", "New problems"), ("resolved", "Resolved")):
            rows = diff[k]; h.append(f"<p><b>{lab}: {len(rows)}</b></p>")
            if rows: h.append("<table><tbody>" + "".join(f"<tr><td>{E(x['host'])}</td><td><code>{E(x['id'])}</code></td><td>{E(x['status'])}</td><td>{E(x['title'])}</td></tr>" for x in rows[:200]) + "</tbody></table>")
    h.append("<h2>Most common problems across the network</h2>")
    cnt = {}
    for s in sites:
        for r in s["results"]:
            if r["status"] in ("FAIL", "WARN"): cnt.setdefault((r["id"], r["title"], r["severity"]), set()).add(s["host"])
    h.append("<table><thead><tr><th>Check</th><th>Severity</th><th>Sites</th></tr></thead><tbody>" + "".join(f"<tr><td><code>{E(i)}</code> {E(tt)}</td><td>{E(sv)}</td><td>{len(hs)}: {E(', '.join(sorted(hs))[:140])}</td></tr>" for (i, tt, sv), hs in sorted(cnt.items(), key=lambda x: (SEV_ORDER.index(x[0][2]) if x[0][2] in SEV_ORDER else 9, -len(x[1])))[:25]) + "</tbody></table>")
    for s in sites:
        h.append(f"<h2 class='site' id='{E(s['host'])}'>{E(s['name'])} <span class='m'>{E(s['host'])}</span> · grade {s['grade']} ({s['score']})</h2>")
        order = {"FAIL": 0, "WARN": 1, "INCONCLUSIVE": 2, "INFO": 3, "MANUAL": 4, "PASS": 5}
        rs = sorted(s["results"], key=lambda r: (order.get(r["status"], 9), SEV_ORDER.index(r["severity"]) if r["severity"] in SEV_ORDER else 9, r["id"]))
        def row(r):
            kb = f" <a href='{REPO}/blob/main/{E(r['kb'])}'>how to fix</a>" if r.get("kb") else ""
            return f"<tr><td><span class='pill' style='background:{COLORS.get(r['status'],'#6e7781')}'>{r['status']}</span></td><td><code>{E(r['id'])}</code> {E(r['title'])}{kb}<div class='m'>{E(r['detail'])}</div>{evidence_html(r, pdf)}</td><td>{E(r['severity'])}</td></tr>"
        top = [r for r in rs if r["status"] in ("FAIL", "WARN", "INCONCLUSIVE", "INFO")]; rest = [r for r in rs if r["status"] not in ("FAIL", "WARN", "INCONCLUSIVE", "INFO")]
        h.append("<table><tbody>" + "".join(row(r) for r in top) + "</tbody></table>" if top else "<p class='m'>No problems found.</p>")
        if pdf: h.append(f"<p><b>{len(rest)} passed or manual checks</b></p><table class='mini'><tbody>" + "".join(f"<tr><td>{r['status']}</td><td><code>{E(r['id'])}</code> {E(r['title'])}</td><td>{E(r['severity'])}</td></tr>" for r in rest) + "</tbody></table>")
        else: h.append(f"<details><summary>{len(rest)} passed or manual checks</summary><table><tbody>" + "".join(row(r) for r in rest) + "</tbody></table></details>")
    h.append(f"<div class='foot'><div class='logo'>{LOGO}</div><div><b>Profitell Security Consulting</b> · <a href='{HOME}'>profitell.com</a><br>Everyday Security {VERSION} (Alpha) · run {E(run_id)} · Only test sites you own or may test. Not legal or compliance advice.</div></div></main></body></html>")
    return "".join(h)

def to_markdown(run, run_id, diff=None):
    t, avg = fleet_numbers(run); L = [f"# Everyday Security report {run_id}", "", f"Profitell Security Consulting · {HOME} · v{VERSION}", "", f"{len(run['sites'])} sites · average score {avg} · {t['FAIL']} fail · {t['WARN']} warn · {t['PASS']} pass · {t['INCONCLUSIVE']} inconclusive · {t['MANUAL']} manual", "", "| Site | Grade | Score | Fail | Warn |", "|---|---|---:|---:|---:|"]
    for s in run["sites"]: L.append(f"| {s['host']} | {s['grade']} | {s['score']} | {s['tally'].get('FAIL',0)} | {s['tally'].get('WARN',0)} |")
    if diff: L += ["", f"Since {diff['previous']}: {len(diff['new'])} new problems, {len(diff['resolved'])} resolved."]
    for s in run["sites"]:
        bad = [r for r in s["results"] if r["status"] in ("FAIL", "WARN", "INCONCLUSIVE")]
        if bad: L += ["", f"## {s['host']}", ""] + [f"- **{r['status']}** `{r['id']}` {r['title']}: {r['detail']}" for r in bad]
    return "\n".join(L) + "\n"

def to_csv(run):
    b = io.StringIO(); w = csv.writer(b); w.writerow(["host", "check_id", "status", "severity", "pillar", "title", "detail", "kb", "confidence", "evidence"])
    for s in run["sites"]:
        for r in s["results"]: w.writerow([s["host"], r["id"], r["status"], r["severity"], r.get("pillar", ""), r["title"], r["detail"], r.get("kb") or "", r.get("confidence") or "", json.dumps(r["evidence"], sort_keys=True) if r.get("evidence") is not None else ""])
    return b.getvalue()
