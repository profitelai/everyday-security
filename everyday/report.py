"""Reports from a fleet run: self-contained HTML, Markdown and CSV."""
import csv, html, io, json, os, urllib.parse
from . import HOME, REPO, VERSION
from .model import SEV_ORDER, tally
from .charts import STATUS_COLOR, donut, grade_color, hbar, ring, stacked
from .where import cloudflare_summary, where

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
tr,.panel,.sc,.alpha,.top,.cfbox{break-inside:avoid}.hero{grid-template-columns:1fr 1.15fr 1fr;gap:10px}.cards{grid-template-columns:repeat(2,1fr)}thead{display:table-header-group}h2{break-after:avoid}h2.site{break-before:page}details>summary{display:none}a{color:inherit;text-decoration:none}
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

GRADE_WORDS = {"A": "Strong", "B": "Good", "C": "Fair", "D": "Weak", "F": "Poor"}
SEV_COLOR = {"critical": "#8b0000", "high": "#cf222e", "medium": "#d9730d", "low": "#bf8700"}
STATUS_LABEL = [("FAIL", "Fail"), ("WARN", "Warning"), ("INCONCLUSIVE", "Inconclusive"), ("MANUAL", "Manual check"), ("PASS", "Pass")]

def _grade(score_):
    return "A" if score_ >= 90 else "B" if score_ >= 80 else "C" if score_ >= 70 else "D" if score_ >= 60 else "F"

def _where_line(r, edge):
    layer, cf, hint = where(r["id"])
    if not layer: return ""
    chip = ""
    if cf in ("yes", "partly") and edge == "cloudflare": chip = f"<span class='cf'>{'Fix in Cloudflare' if cf == 'yes' else 'Cloudflare helps'}</span>"
    elif cf in ("yes", "partly"): chip = f"<span class='cf off'>{'Cloudflare can do this' if cf == 'yes' else 'Cloudflare can help'}</span>"
    return f"<div class='where'>{chip}<span class='m'>Where to fix: {E(layer)}</span>" + (f"<div class='m hint'>{E(hint)}</div>" if hint else "") + "</div>"

def _open(sites):
    out = []
    for s in sites:
        for r in s["results"]:
            if r["status"] in ("FAIL", "WARN"): out.append((s, r))
    return out

def to_html(run, run_id, diff=None, pdf=False):
    t, avg = fleet_numbers(run); sites = run["sites"]; pillars = sorted({r.get("pillar", "") for s in sites for r in s["results"] if r.get("pillar")})
    gavg = _grade(avg); total = sum(t.values()); opened = _open(sites)
    sev = {k: sum(1 for _, r in opened if r["severity"] == k) for k in ("critical", "high", "medium", "low")}
    cf_sites = [x for x in sites if x.get("edge") == "cloudflare"]; cfs = cloudflare_summary([r for x in cf_sites for r in x["results"]])
    legend = "".join(f"<div class='lg'><i style='background:{STATUS_COLOR[k]}'></i>{lab}<b>{t.get(k, 0)}</b></div>" for k, lab in STATUS_LABEL)
    sevbars = "".join(f"<div class='sv'><span>{k.capitalize()}</span>{hbar(v, max(max(sev.values()), 1), SEV_COLOR[k], 130)}<b>{v}</b></div>" for k, v in sev.items())
    cfbox = (f'<div class="cfbox"><b>{cfs["yes"]}</b> of {cfs["open"]} open findings on the {len(cf_sites)} Cloudflare site{"s" if len(cf_sites) != 1 else ""} can be fixed in Cloudflare<div class="m" style="font-size:12px">{cfs["partly"]} more where Cloudflare helps; {cfs["no"]} need the server, the application or a person.</div></div>' if cf_sites else '<div class="cfbox">No scanned site is behind Cloudflare, so these fixes are made on the web server and at the DNS provider.</div>')
    h = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Everyday Security report {E(run_id)}</title>
<style>:root{{--bg:#fff;--tx:#111827;--mut:#4b5563;--line:#e5e7eb;--panel:#f9fafb}}@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--tx:#e6edf3;--mut:#9ca3af;--line:#30363d;--panel:#161b22}}}}
body{{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif}}main{{max-width:1100px;margin:auto;padding:24px}}h1{{font-size:22px;margin:0}}h2{{font-size:17px;margin:30px 0 10px}}
a{{color:#0969da}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}}th{{background:var(--panel);font-size:11px;letter-spacing:.3px;text-transform:uppercase;color:var(--mut)}}
.pill{{display:inline-block;border-radius:99px;padding:1px 9px;font-size:11px;font-weight:700;color:#fff}}.m{{color:var(--mut)}}.cell{{width:20px;height:20px;border-radius:5px;display:inline-block}}code{{font-size:12px}}details{{margin:8px 0}}summary{{cursor:pointer;font-weight:600}}
.tag{{border:1px solid var(--line);border-radius:99px;padding:0 7px;font-size:11px;color:var(--mut);margin-right:3px}}
.hero{{display:grid;grid-template-columns:1.05fr 1.2fr 1.1fr;gap:14px;margin:16px 0}}.panel{{border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--bg)}}.panel h3{{margin:0 0 10px;font-size:12px;letter-spacing:.4px;text-transform:uppercase;color:var(--mut)}}
.hero .center{{display:flex;flex-direction:column;align-items:center;text-align:center}}.big{{font-size:15px;font-weight:700;margin-top:8px}}.row{{display:flex;align-items:center;gap:16px}}
.lg{{display:flex;align-items:center;gap:8px;font-size:13px;margin:3px 0}}.lg i{{width:10px;height:10px;border-radius:3px;display:inline-block}}.lg b{{margin-left:auto;padding-left:14px}}
.sv{{display:flex;align-items:center;gap:8px;font-size:13px;margin:5px 0}}.sv span{{width:58px}}.sv b{{margin-left:auto}}
.cfbox{{margin-top:12px;padding:10px 12px;border-radius:10px;background:var(--panel);font-size:13px}}.cfbox b{{font-size:20px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin:12px 0}}.sc{{border:1px solid var(--line);border-radius:14px;padding:14px;display:flex;gap:14px;align-items:center;text-decoration:none;color:inherit}}.sc b{{font-size:15px}}
.chip{{display:inline-block;border-radius:6px;padding:0 7px;font-size:11px;font-weight:700;color:#fff}}.edge{{font-size:11px;color:var(--mut)}}
.top{{border:1px solid var(--line);border-left:4px solid #cf222e;border-radius:10px;padding:12px 16px}}.top ol{{margin:6px 0 0 18px;padding:0}}.top li{{margin:6px 0}}
.cf{{display:inline-block;background:#f6851f;color:#fff;border-radius:6px;padding:0 7px;font-size:11px;font-weight:700;margin-right:8px}}.cf.off{{background:transparent;color:#b45309;border:1px solid #f6851f}}.where{{margin-top:4px;font-size:12px}}.hint{{margin-top:2px}}
.pb{{display:grid;grid-template-columns:190px 1fr 70px;gap:8px;align-items:center;font-size:12px;margin:4px 0}}.sitehead{{display:flex;gap:22px;align-items:center;margin:8px 0 14px}}
.alpha{{border:1px solid var(--line);border-left:4px solid #bf8700;background:var(--panel);padding:8px 12px;border-radius:6px;font-size:12px;margin:12px 0}}
.brandbar{{display:flex;align-items:center;gap:14px;padding-bottom:14px;border-bottom:2px solid var(--tx);margin-bottom:12px}}.brandbar .logo{{width:44px;height:44px;flex:none}}.brandbar h1{{font-size:24px;letter-spacing:-.3px}}.brandbar .sub{{color:var(--mut);font-size:13px}}
.foot{{margin-top:34px;border-top:1px solid var(--line);padding-top:10px;display:flex;align-items:center;gap:10px;font-size:11px;color:var(--mut)}}.foot .logo{{width:26px;height:26px;flex:none}}.foot b{{color:var(--tx)}}.mini td{{font-size:11px;padding:3px 8px}}
@media(max-width:820px){{.hero{{grid-template-columns:1fr}}.pb{{grid-template-columns:130px 1fr 60px}}}}
{PRINT_CSS}</style></head><body><main>
<div class="brandbar"><div class="logo">{LOGO}</div><div><h1>Everyday Security report</h1><div class="sub">Security check by Profitell Security Consulting · run {E(run_id)} · {E(run['started'][:10])}</div></div></div>
<div class="m">{E(run['started'][:19])} UTC · v{VERSION} · {len(sites)} site{'s' if len(sites) != 1 else ''} · {total} results · rules loaded {run['rules_loaded']} (pack {E(run['pack_hash'])}) · {'deep scan' if run['deep'] else 'standard scan'}</div>
<div class="hero">
<div class="panel center"><h3>Overall score</h3>{ring(avg, 150, 15, grade_color(gavg), small="out of 100", label=f"average score {avg} out of 100")}<div class="big" style="color:{grade_color(gavg)}">Grade {gavg} · {GRADE_WORDS[gavg]}</div><div class="m" style="font-size:12px;margin-top:4px">average of {len(sites)} site{'s' if len(sites) != 1 else ''}</div></div>
<div class="panel"><h3>All results</h3><div class="row">{donut([(t.get(k, 0), STATUS_COLOR[k]) for k, _ in STATUS_LABEL], 140, 18, total, "results")}<div style="flex:1">{legend}</div></div></div>
<div class="panel"><h3>Open findings</h3>{sevbars}{cfbox}</div>
</div>
<div class="alpha"><b>Alpha (v{VERSION}).</b> The checks are drafts written from public sources and have not been reviewed by a named security professional or measured for accuracy. A finding can be wrong, and a clean result is not proof of safety. Use this report as a starting point and confirm each finding before changing anything. The score is a comparison aid, not a certification: each failed check costs twice its severity weight, each warning one weight. Manual and inconclusive items are not scored.</div>
<h2>Sites</h2><div class="cards">"""]
    for s in sites:
        tt = s["tally"]; edge = "Behind Cloudflare" if s.get("edge") == "cloudflare" else "Served directly"; lbl = f"{s['host']} score {s['score']}"
        h.append(f"<a class='sc' href='#{E(s['host'])}'>{ring(s['score'], 84, 9, grade_color(s['grade']), label=lbl)}<div><b>{E(s['name'])}</b><div class='m' style='font-size:12px'>{E(s['host'])}</div><div style='margin:4px 0'><span class='chip' style='background:{grade_color(s['grade'])}'>Grade {s['grade']}</span> <span class='edge'>{edge}</span></div><div class='m' style='font-size:12px'>{tt.get('FAIL', 0)} fail · {tt.get('WARN', 0)} warn · {tt.get('PASS', 0)} pass</div></div></a>")
    h.append("</div>")
    if opened:
        order = sorted(opened, key=lambda x: (0 if x[1]["status"] == "FAIL" else 1, SEV_ORDER.index(x[1]["severity"]) if x[1]["severity"] in SEV_ORDER else 9, x[0]["host"]))
        seen = set(); picks = []
        for sx, r in order:
            if r["id"] in seen: continue
            seen.add(r["id"]); picks.append((sx, r))
            if len(picks) == 6: break
        h.append("<h2>Fix these first</h2><div class='top'><div class='m' style='font-size:12px'>Ordered by status and severity. Each item can affect more than one site; see the site sections.</div><ol>")
        for sx, r in picks:
            hosts = sorted({x["host"] for x, y in opened if y["id"] == r["id"]}); layer, cf, _ = where(r["id"])
            h.append(f"<li><span class='pill' style='background:{SEV_COLOR.get(r['severity'], '#6e7781')}'>{E(r['severity'])}</span> <b>{E(r['title'])}</b> <span class='m'>({E(r['id'])}; {E(', '.join(hosts))})</span>" + (f"<div class='m' style='font-size:12px'>Where to fix: {E(layer)}{' · Cloudflare can do this' if cf == 'yes' and any(x.get('edge') == 'cloudflare' and x['host'] in hosts for x in sites) else ''}</div>" if layer else "") + "</li>")
        h.append("</ol></div>")
    h.append("<h2>Results by pillar</h2><table><thead><tr><th>Site</th><th>Grade</th><th>Score</th><th>Fail</th><th>Warn</th><th>Pass</th>" + "".join(f"<th title='{E(p)}'>{E(p[:6])}</th>" for p in pillars) + "</tr></thead><tbody>")
    for s in sites:
        tt = s["tally"]; h.append(f"<tr><td><a href='#{E(s['host'])}'><b>{E(s['name'])}</b></a><div class='m'>{E(s['host'])}</div></td><td><b style='color:{grade_color(s['grade'])}'>{s['grade']}</b></td><td>{s['score']}</td><td>{tt.get('FAIL',0)}</td><td>{tt.get('WARN',0)}</td><td>{tt.get('PASS',0)}</td>")
        for p in pillars:
            w = worst([r for r in s["results"] if r.get("pillar") == p]); h.append(f"<td>{'<span class=cell title=%s style=background:%s></span>' % (repr(p + ': ' + w), COLORS[w]) if w else ''}</td>")
        h.append("</tr>")
    h.append("</tbody></table><p class='m' style='font-size:12px'>Cell colour = worst result in that pillar for that site (red fail, amber warn, green pass, grey manual).</p>")
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
        edge = s.get("edge"); sc = cloudflare_summary(s["results"]); tt = s["tally"]
        pill_rows = []
        for p in pillars:
            rs_ = [r for r in s["results"] if r.get("pillar") == p]
            if not rs_: continue
            c = {k: sum(1 for r in rs_ if r["status"] == k) for k in ("FAIL", "WARN", "INCONCLUSIVE", "MANUAL", "PASS", "INFO")}
            pill_rows.append(f"<div class='pb'><span>{E(p)}</span>{stacked([(c['FAIL'], STATUS_COLOR['FAIL']), (c['WARN'], STATUS_COLOR['WARN']), (c['INCONCLUSIVE'], STATUS_COLOR['INCONCLUSIVE']), (c['PASS'], STATUS_COLOR['PASS']), (c['MANUAL'] + c['INFO'], STATUS_COLOR['MANUAL'])], 220)}<span class='m'>{len(rs_)} checks</span></div>")
        hostspan = "" if s["name"] == s["host"] else " <span class='m'>" + E(s["host"]) + "</span>"
        h.append(f"<h2 class='site' id='{E(s['host'])}'>{E(s['name'])}{hostspan}</h2>")
        h.append(f"<div class='sitehead'>{ring(s['score'], 120, 13, grade_color(s['grade']), label=s['host'] + ' score')}<div style='flex:1'><div style='font-size:16px;font-weight:700;color:{grade_color(s['grade'])}'>Grade {s['grade']} · {GRADE_WORDS[s['grade']]}</div><div class='m' style='margin:2px 0 8px'>{tt.get('FAIL', 0)} fail · {tt.get('WARN', 0)} warnings · {tt.get('PASS', 0)} pass · {tt.get('MANUAL', 0)} manual · {'behind Cloudflare' if edge == 'cloudflare' else 'served directly, not through Cloudflare'}</div>"
                 + (f"<div class='cfbox' style='margin:0 0 8px'><b>{sc['yes']}</b> of {sc['open']} open findings can be fixed in Cloudflare, {sc['partly']} partly</div>" if sc['open'] and edge == 'cloudflare' else "") + "".join(pill_rows) + "</div></div>")
        order = {"FAIL": 0, "WARN": 1, "INCONCLUSIVE": 2, "INFO": 3, "MANUAL": 4, "PASS": 5}
        rs = sorted(s["results"], key=lambda r: (order.get(r["status"], 9), SEV_ORDER.index(r["severity"]) if r["severity"] in SEV_ORDER else 9, r["id"]))
        def row(r, edge=edge):
            kb = f" <a href='{REPO}/blob/main/{E(r['kb'])}'>how to fix</a>" if r.get("kb") else ""
            wl = _where_line(r, edge) if r["status"] in ("FAIL", "WARN") else ""
            return f"<tr><td><span class='pill' style='background:{COLORS.get(r['status'],'#6e7781')}'>{r['status']}</span></td><td><code>{E(r['id'])}</code> <b>{E(r['title'])}</b>{kb}<div class='m'>{E(r['detail'])}</div>{wl}{evidence_html(r, pdf)}</td><td>{E(r['severity'])}</td></tr>"
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
