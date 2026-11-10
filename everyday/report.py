"""Reports from a fleet run: self-contained HTML, Markdown and CSV."""
import csv, html, io
from . import HOME, REPO, VERSION
from .model import SEV_ORDER, tally

COLORS = {"FAIL": "#d1242f", "WARN": "#bf8700", "PASS": "#1a7f37", "MANUAL": "#6e7781", "INFO": "#0969da"}
E = html.escape

def worst(results):
    for s in ("FAIL", "WARN", "PASS", "MANUAL", "INFO"):
        if any(r["status"] == s for r in results): return s
    return ""

def fleet_numbers(run):
    sites = run["sites"]; t = {"FAIL": 0, "WARN": 0, "PASS": 0, "MANUAL": 0, "INFO": 0}
    for s in sites:
        for k, v in tally(s["results"]).items(): t[k] = t.get(k, 0) + v
    avg = round(sum(s["score"] for s in sites) / len(sites)) if sites else 0
    return t, avg

def to_html(run, run_id, diff=None):
    t, avg = fleet_numbers(run); sites = run["sites"]; pillars = sorted({r.get("pillar", "") for s in sites for r in s["results"] if r.get("pillar")})
    h = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Everyday Security report {E(run_id)}</title>
<style>:root{{--bg:#fff;--tx:#1f2328;--mut:#656d76;--line:#d0d7de;--panel:#f6f8fa}}@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--tx:#e6edf3;--mut:#8b949e;--line:#30363d;--panel:#161b22}}}}
body{{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,Segoe UI,sans-serif}}main{{max-width:1200px;margin:auto;padding:20px}}h1{{font-size:22px;margin:0}}h2{{font-size:16px;margin:26px 0 8px}}
a{{color:#0969da}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}}th{{background:var(--panel);font-size:12px;color:var(--mut)}}
.cards{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:110px}}.card b{{font-size:24px;display:block}}
.pill{{display:inline-block;border-radius:99px;padding:0 8px;font-size:11px;color:#fff}}.g{{font-weight:700;font-size:18px}}.m{{color:var(--mut)}}.cell{{width:22px;height:22px;border-radius:4px;display:inline-block}}code{{font-size:12px}}details{{margin:8px 0}}summary{{cursor:pointer;font-weight:600}}
.tag{{border:1px solid var(--line);border-radius:99px;padding:0 7px;font-size:11px;color:var(--mut);margin-right:3px}}</style></head><body><main>
<h1>Everyday Security report</h1><div class="m">Profitell Security Consulting · <a href="{HOME}">profitell.com</a> · <a href="{REPO}">{E(REPO.split('//')[1])}</a> · v{VERSION} · run {E(run_id)} · {E(run['started'][:19])} UTC · rules loaded {run['rules_loaded']} (pack {E(run['pack_hash'])}) · {'deep scan' if run['deep'] else 'standard scan'}</div>
<div class="cards"><div class="card"><b>{len(sites)}</b>sites</div><div class="card"><b>{avg}</b>average score</div><div class="card"><b style="color:{COLORS['FAIL']}">{t['FAIL']}</b>fail</div><div class="card"><b style="color:{COLORS['WARN']}">{t['WARN']}</b>warn</div><div class="card"><b style="color:{COLORS['PASS']}">{t['PASS']}</b>pass</div><div class="card"><b>{t['MANUAL']}</b>manual</div></div>
<p class="m">The score is a comparison aid (each failed check costs twice its severity weight, each warning one weight), not a certification. MANUAL items could not be judged from outside and are not scored.</p>
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
        h.append(f"<h2 id='{E(s['host'])}'>{E(s['name'])} <span class='m'>{E(s['host'])}</span> · grade {s['grade']} ({s['score']})</h2>")
        order = {"FAIL": 0, "WARN": 1, "INFO": 2, "MANUAL": 3, "PASS": 4}
        rs = sorted(s["results"], key=lambda r: (order.get(r["status"], 9), SEV_ORDER.index(r["severity"]) if r["severity"] in SEV_ORDER else 9, r["id"]))
        def row(r):
            kb = f" <a href='{REPO}/blob/main/{E(r['kb'])}'>how to fix</a>" if r.get("kb") else ""
            return f"<tr><td><span class='pill' style='background:{COLORS.get(r['status'],'#6e7781')}'>{r['status']}</span></td><td><code>{E(r['id'])}</code> {E(r['title'])}{kb}<div class='m'>{E(r['detail'])}</div></td><td>{E(r['severity'])}</td></tr>"
        top = [r for r in rs if r["status"] in ("FAIL", "WARN", "INFO")]; rest = [r for r in rs if r["status"] not in ("FAIL", "WARN", "INFO")]
        h.append("<table><tbody>" + "".join(row(r) for r in top) + "</tbody></table>" if top else "<p class='m'>No problems found.</p>")
        h.append(f"<details><summary>{len(rest)} passed or manual checks</summary><table><tbody>" + "".join(row(r) for r in rest) + "</tbody></table></details>")
    h.append(f"<p class='m'>Generated by Everyday Security {VERSION}, Profitell Security Consulting. Only test sites you own or may test.</p></main></body></html>")
    return "".join(h)

def to_markdown(run, run_id, diff=None):
    t, avg = fleet_numbers(run); L = [f"# Everyday Security report {run_id}", "", f"Profitell Security Consulting · {HOME} · v{VERSION}", "", f"{len(run['sites'])} sites · average score {avg} · {t['FAIL']} fail · {t['WARN']} warn · {t['PASS']} pass · {t['MANUAL']} manual", "", "| Site | Grade | Score | Fail | Warn |", "|---|---|---:|---:|---:|"]
    for s in run["sites"]: L.append(f"| {s['host']} | {s['grade']} | {s['score']} | {s['tally'].get('FAIL',0)} | {s['tally'].get('WARN',0)} |")
    if diff: L += ["", f"Since {diff['previous']}: {len(diff['new'])} new problems, {len(diff['resolved'])} resolved."]
    for s in run["sites"]:
        bad = [r for r in s["results"] if r["status"] in ("FAIL", "WARN")]
        if bad: L += ["", f"## {s['host']}", ""] + [f"- **{r['status']}** `{r['id']}` {r['title']}: {r['detail']}" for r in bad]
    return "\n".join(L) + "\n"

def to_csv(run):
    b = io.StringIO(); w = csv.writer(b); w.writerow(["host", "check_id", "status", "severity", "pillar", "title", "detail", "kb"])
    for s in run["sites"]:
        for r in s["results"]: w.writerow([s["host"], r["id"], r["status"], r["severity"], r.get("pillar", ""), r["title"], r["detail"], r.get("kb") or ""])
    return b.getvalue()
