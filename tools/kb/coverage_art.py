"""SVG graphics for docs/coverage: white background, black type, original line icons (no third-party logos).
Used by build_coverage.py. Standard library only."""
import html

FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
INK, MUTE, LINE, SOFT = "#111827", "#4b5563", "#e5e7eb", "#f9fafb"
STATUS = {"PASS": "#1a7f37", "WARN": "#9a6700", "FAIL": "#cf222e", "INCONCLUSIVE": "#8250df", "MANUAL": "#57606a"}
AUTO, HOST, LIST = "#15803d", "#111827", "#d1d5db"     # automatic / server audit / checklist
E = html.escape

ICONS = {   # 24x24 line icons, drawn for this project
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    "mail": '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    "server": '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
    "cube": '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12L4 7.5M12 12v9"/>',
    "cloud": '<path d="M7 18a4 4 0 010-8 5 5 0 019.6-1.2A3.6 3.6 0 0117 18z"/>',
    "shield": '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5L16 9.5"/>',
    "lock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    "list": '<path d="M4 6h16M4 12h10M4 18h16"/>',
    "network": '<circle cx="6" cy="12" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 12h4l4-5M12 12l4 5"/>',
    "code": '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 6l-3 12"/>',
    "page": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 9v11"/>',
    "backup": '<path d="M12 4v10M8 10l4 4 4-4M5 19h14"/>',
    "alert": '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
    "people": '<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3.5 2.5-6 6-6s6 2.5 6 6M16 11a3 3 0 100-6M18 14c2 .7 3 2.5 3 5"/>',
    "link": '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>',
    "eye": '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M21 21l-5-5"/>',
    "file": '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 13h6M9 17h6"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
}
PILLAR_ICON = {"tls": "lock", "http-headers": "list", "mail-authentication": "mail", "dns": "network", "web-app": "code", "wordpress-and-cms": "page", "server-hardening": "server",
               "containers": "cube", "backups-and-recovery": "backup", "incident-response": "alert", "cloud-and-saas-accounts": "cloud", "vendor-and-supply-chain": "link", "privacy-compliance": "eye"}


def icon(name, x, y, size=28, color=INK, sw=1.7):
    s = size / 24
    return f'<g transform="translate({x} {y}) scale({s:.3f})" fill="none" stroke="{color}" stroke-width="{sw}" stroke-linecap="round" stroke-linejoin="round">{ICONS[name]}</g>'


def head(w, h, label, border=True):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{E(label)}">'
            f'<rect width="{w}" height="{h}" rx="16" fill="#ffffff"' + (f' stroke="{LINE}"' if border else "") + "/>")


def t(x, y, s, size=14, weight=400, fill=INK, anchor="start"):
    return f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{E(str(s))}</text>'


def chip(x, y, label, color, filled=False):
    w = 14 + 6.4 * len(label)
    if filled: return f'<rect x="{x}" y="{y}" width="{w:.0f}" height="20" rx="10" fill="{color}"/>' + t(x + w / 2, y + 14, label, 10, 700, "#ffffff", "middle"), w
    return f'<rect x="{x}" y="{y}" width="{w:.0f}" height="20" rx="10" fill="#ffffff" stroke="{color}"/>' + t(x + w / 2, y + 14, label, 10, 700, color, "middle"), w


def logo(x, y, size=64):
    """Project mark: a shield with a check on a white tile (original artwork)."""
    s = size / 24
    return (f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="{size * 0.22:.0f}" fill="{INK}"/>'
            f'<g transform="translate({x + size * 0.16:.1f} {y + size * 0.16:.1f}) scale({s * 0.68:.3f})" fill="none" stroke="#ffffff" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">{ICONS["shield"]}</g>')


def overview(n, version):
    w, h = 900, 250; o = [head(w, h, "Everyday Security at a glance"), logo(36, 34, 64), t(116, 66, "Everyday Security", 34, 800), t(116, 92, "Practical security checks for websites, servers and email", 16, 400, MUTE)]
    x = 116
    for label, color in ((f"ALPHA {version}", "#9a6700"), ("PYTHON, NO DEPENDENCIES", INK), ("READ-ONLY CHECKS", "#15803d")):
        c, wd = chip(x, 106, label, color); o.append(c); x += wd + 8
    o.append(f'<line x1="36" y1="150" x2="{w - 36}" y2="150" stroke="{LINE}"/>')
    tiles = [(n["checks"], "security checks"), (n["pillars"], "pillars"), (n["auto"], "run automatically"), (n["host"], "server audit"), (n["rules"], "scan rules"), (n["sources"], "public sources")]
    cw = (w - 72) / len(tiles)
    for i, (v, l) in enumerate(tiles):
        cx = 36 + cw * i + cw / 2
        o += [t(cx, 192, v, 38, 800, INK, "middle"), t(cx, 214, l, 12, 400, MUTE, "middle")]
        if i: o.append(f'<line x1="{36 + cw * i:.0f}" y1="168" x2="{36 + cw * i:.0f}" y2="222" stroke="{LINE}"/>')
    o.append(t(w - 36, 242, "Profitell Security Consulting · profitell.com", 11, 400, MUTE, "end"))
    return "".join(o) + "</svg>\n"


def targets(items):
    """items: [(icon, title, subtitle, n_checks, chips)] in 3 columns."""
    cols, cw, chh, gap, pad = 3, 272, 132, 16, 24; rows = (len(items) + cols - 1) // cols; w = pad * 2 + cols * cw + (cols - 1) * gap; h = 84 + rows * chh + (rows - 1) * gap + pad
    o = [head(w, h, "What you can scan"), t(pad, 40, "What you can point it at", 22, 800), t(pad, 62, "Eight kinds of target, one checklist each", 13, 400, MUTE)]
    for i, (ic, title, sub, n, chips) in enumerate(items):
        x = pad + (i % cols) * (cw + gap); y = 84 + (i // cols) * (chh + gap)
        o += [f'<rect x="{x}" y="{y}" width="{cw}" height="{chh}" rx="12" fill="{SOFT}" stroke="{LINE}"/>', f'<rect x="{x + 16}" y="{y + 16}" width="44" height="44" rx="10" fill="#ffffff" stroke="{LINE}"/>', icon(ic, x + 24, y + 24, 28),
              t(x + 72, y + 34, title, 16, 700), t(x + 72, y + 54, sub, 12, 400, MUTE), t(x + cw - 16, y + chh - 24, f"{n} checks", 13, 700, INK, "end")]
        cx = x + 16
        for label, color in chips:
            c, wd = chip(cx, y + chh - 38, label, color); o.append(c); cx += wd + 6
    return "".join(o) + "</svg>\n"


def pillars(cards):
    """cards: [(icon, title, n, auto, host, manual)]."""
    cols, cw, chh, gap, pad = 4, 201, 118, 14, 24; rows = (len(cards) + cols - 1) // cols; w = pad * 2 + cols * cw + (cols - 1) * gap; h = 84 + rows * chh + (rows - 1) * gap + pad
    o = [head(w, h, "The 13 pillars"), t(pad, 40, "13 pillars", 22, 800), t(pad, 62, "Each pillar groups checks that share a theme. The bar shows how they are run.", 13, 400, MUTE)]
    for i, (ic, title, n, a, hs, m) in enumerate(cards):
        x = pad + (i % cols) * (cw + gap); y = 84 + (i // cols) * (chh + gap)
        o += [f'<rect x="{x}" y="{y}" width="{cw}" height="{chh}" rx="12" fill="#ffffff" stroke="{LINE}"/>', icon(ic, x + 16, y + 16, 26), t(x + cw - 16, y + 38, n, 24, 800, INK, "end")]
        words, lines, cur = title.split(), [], ""
        for wd in words:
            if len(cur + " " + wd) > 21 and cur: lines.append(cur); cur = wd
            else: cur = (cur + " " + wd).strip()
        lines.append(cur)
        for j, ln in enumerate(lines[:2]): o.append(t(x + 16, y + 68 + j * 16, ln, 13, 700))
        bx, by, bw = x + 16, y + chh - 16, cw - 32; tot = max(a + hs + m, 1); cx = bx
        for v, color in ((a, AUTO), (hs, HOST), (m, LIST)):
            if v: o.append(f'<rect x="{cx:.1f}" y="{by}" width="{bw * v / tot:.1f}" height="6" fill="{color}"/>'); cx += bw * v / tot
    return "".join(o) + "</svg>\n"


def legend(x, y):
    o = []
    for color, label in ((AUTO, "automatic outside scan"), (HOST, "server audit"), (LIST, "guided checklist")):
        o += [f'<rect x="{x}" y="{y}" width="12" height="12" rx="2" fill="{color}"/>', t(x + 18, y + 10, label, 12, 400, MUTE)]; x += 28 + 6.6 * len(label)
    return "".join(o)


def by_pillar(rows):
    w, rowh, left, bar = 900, 30, 250, 560; h = 100 + rowh * len(rows); mx = max(r[1] + r[2] + r[3] for r in rows)
    o = [head(w, h, "Checks per pillar by how they are run"), t(24, 40, "Checks per pillar", 22, 800), legend(24, 56)]
    for i, (name, a, hs, m) in enumerate(rows):
        y = 88 + i * rowh; x = left
        o.append(t(left - 12, y + 15, name, 13, 400, INK, "end"))
        for v, color in ((a, AUTO), (hs, HOST), (m, LIST)):
            if v: wd = v / mx * bar; o.append(f'<rect x="{x:.1f}" y="{y}" width="{wd:.1f}" height="20" fill="{color}"/>'); x += wd
        o.append(t(x + 8, y + 15, a + hs + m, 12, 700, INK))
    return "".join(o) + "</svg>\n"


def how_it_works(n):
    w, h = 900, 352; o = [head(w, h, "How a scan works"), t(24, 40, "How a scan works", 22, 800), t(24, 62, "From a domain name to a report you can act on", 13, 400, MUTE)]
    steps = [("search", "1  Discover", "A domain, its subdomains and mail servers, or an inventory file of sites."),
             ("shield", "2  Check", f"{n['auto']} automatic checks and {n['rules']} data rules from outside; {n['host']} server checks run on the server."),
             ("file", "3  Record evidence", "What was asked, what came back, a timestamp and a confidence level."),
             ("clock", "4  Report and track", "HTML, Markdown, CSV and JSON reports, a score, and what is new or fixed since last time.")]
    cw, gap = 200, 18
    for i, (ic, title, body) in enumerate(steps):
        x = 24 + i * (cw + gap); y = 90
        o += [f'<rect x="{x}" y="{y}" width="{cw}" height="165" rx="12" fill="{SOFT}" stroke="{LINE}"/>', icon(ic, x + 16, y + 16, 28), t(x + 16, y + 68, title, 15, 700)]
        words, line, ln = body.split(), "", 0
        for wd in words:
            if len(line + " " + wd) > 25: o.append(t(x + 16, y + 90 + ln * 16, line.strip(), 12, 400, MUTE)); ln += 1; line = wd
            else: line += " " + wd
        o.append(t(x + 16, y + 90 + ln * 16, line.strip(), 12, 400, MUTE))
        if i < 3: o.append(f'<path d="M{x + cw + 3} {y + 75} l{gap - 6} 0 m-5 -5 l5 5 l-5 5" fill="none" stroke="{INK}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>')
    o.append(t(24, 287, "Every result is one of", 12, 700))
    x = 24
    for label in ("PASS", "WARN", "FAIL", "INCONCLUSIVE", "MANUAL"):
        c, wd = chip(x, 297, label, STATUS[label], filled=True); o.append(c); x += wd + 8
    o.append(t(24, 337, "INCONCLUSIVE = not enough evidence to judge. MANUAL = needs a person. Neither is scored.", 11, 400, MUTE))
    return "".join(o) + "</svg>\n"


def social(n, version):
    w, h = 1280, 640; o = [head(w, h, "Everyday Security", border=False), logo(80, 96, 112), t(220, 150, "Everyday Security", 64, 800), t(220, 196, "Practical security checks for websites, servers and email", 28, 400, MUTE)]
    chips = [("Website", INK), ("WordPress", INK), ("Email", INK), ("DNS", INK), ("Linux server", INK), ("Docker", INK), ("Cloud and SaaS", INK)]
    x = 80
    for label, color in chips:
        wd = 30 + 11.5 * len(label); o += [f'<rect x="{x}" y="270" width="{wd:.0f}" height="44" rx="22" fill="#ffffff" stroke="{INK}" stroke-width="1.5"/>', t(x + wd / 2, 299, label, 20, 600, INK, "middle")]; x += wd + 14
    tiles = [(n["checks"], "security checks"), (n["pillars"], "pillars"), (n["auto"], "run automatically"), (n["host"], "server audit"), (n["sources"], "public sources")]
    cw = (w - 160) / len(tiles)
    o.append(f'<line x1="80" y1="380" x2="{w - 80}" y2="380" stroke="{LINE}" stroke-width="2"/>')
    for i, (v, l) in enumerate(tiles):
        cx = 80 + cw * i + cw / 2; o += [t(cx, 480, v, 80, 800, INK, "middle"), t(cx, 520, l, 22, 400, MUTE, "middle")]
    o.append(t(80, 590, f"Alpha {version} · for systems you own · by Profitell Security Consulting", 20, 400, MUTE))
    return "".join(o) + "</svg>\n"
