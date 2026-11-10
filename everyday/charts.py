"""Small inline-SVG charts for the report: score rings, a status donut and bars. Standard library only.
Colours come from CSS variables so the same SVG works on screen (light or dark) and in the PDF."""
import html, math

GRADE_COLOR = {"A": "#1a7f37", "B": "#3f9b3f", "C": "#bf8700", "D": "#d9730d", "F": "#cf222e"}
STATUS_COLOR = {"FAIL": "#cf222e", "WARN": "#bf8700", "INCONCLUSIVE": "#8250df", "PASS": "#1a7f37", "MANUAL": "#8c959f", "INFO": "#0969da"}
E = html.escape
FONT = "-apple-system,Segoe UI,Helvetica,Arial,sans-serif"


def grade_color(grade): return GRADE_COLOR.get(grade, "#8c959f")


def ring(value, size=120, stroke=12, color="#1a7f37", big=None, small="/ 100", label=""):
    """A circular gauge: value 0..100 fills the ring; the number sits in the middle."""
    r = (size - stroke) / 2; c = size / 2; circ = 2 * math.pi * r; v = max(0, min(100, value)); dash = circ * v / 100
    bs = size * 0.30; ss = size * 0.105
    return (f'<svg class="ring" width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" aria-label="{E(label or f"score {v} of 100")}">'
            f'<circle cx="{c}" cy="{c}" r="{r:.2f}" fill="none" stroke="var(--line)" stroke-width="{stroke}"/>'
            f'<circle cx="{c}" cy="{c}" r="{r:.2f}" fill="none" stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" stroke-dasharray="{dash:.2f} {circ:.2f}" transform="rotate(-90 {c} {c})"/>'
            f'<text x="{c}" y="{c + bs * 0.18:.1f}" text-anchor="middle" font-family="{FONT}" font-size="{bs:.0f}" font-weight="800" fill="var(--tx)">{E(str(big if big is not None else round(v)))}</text>'
            f'<text x="{c}" y="{c + bs * 0.18 + ss * 1.5:.1f}" text-anchor="middle" font-family="{FONT}" font-size="{ss:.0f}" fill="var(--mut)">{E(small)}</text></svg>')


def donut(parts, size=150, stroke=18, big="", small=""):
    """parts: [(value, colour)]. Segments are drawn clockwise from the top with thin gaps."""
    r = (size - stroke) / 2; c = size / 2; circ = 2 * math.pi * r; tot = sum(v for v, _ in parts) or 1
    o = [f'<svg class="donut" width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" aria-label="{E(small)}"><circle cx="{c}" cy="{c}" r="{r:.2f}" fill="none" stroke="var(--line)" stroke-width="{stroke}"/>']
    off = 0.0
    for v, col in parts:
        if v <= 0: continue
        seg = circ * v / tot; gap = 2 if len([1 for p, _ in parts if p > 0]) > 1 else 0
        o.append(f'<circle cx="{c}" cy="{c}" r="{r:.2f}" fill="none" stroke="{col}" stroke-width="{stroke}" stroke-dasharray="{max(seg - gap, 0.5):.2f} {circ:.2f}" stroke-dashoffset="{-off:.2f}" transform="rotate(-90 {c} {c})"/>'); off += seg
    o.append(f'<text x="{c}" y="{c + 6}" text-anchor="middle" font-family="{FONT}" font-size="{size * 0.22:.0f}" font-weight="800" fill="var(--tx)">{E(str(big))}</text>'
             f'<text x="{c}" y="{c + 6 + size * 0.13:.0f}" text-anchor="middle" font-family="{FONT}" font-size="{size * 0.085:.0f}" fill="var(--mut)">{E(small)}</text></svg>')
    return "".join(o)


def hbar(value, total, color, width=160, height=8):
    w = 0 if not total else max(2, width * value / total) if value else 0
    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"><rect width="{width}" height="{height}" rx="{height / 2}" fill="var(--line)"/>' + (f'<rect width="{w:.1f}" height="{height}" rx="{height / 2}" fill="{color}"/>' if w else "") + "</svg>"


def stacked(parts, width=180, height=8):
    """parts: [(value, colour)] as one horizontal stacked bar."""
    tot = sum(v for v, _ in parts) or 1; x = 0.0; o = [f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"><rect width="{width}" height="{height}" rx="{height / 2}" fill="var(--line)"/><clipPath id="cp{abs(hash(tuple(parts))) % 99999}"><rect width="{width}" height="{height}" rx="{height / 2}"/></clipPath><g clip-path="url(#cp{abs(hash(tuple(parts))) % 99999})">']
    for v, col in parts:
        if v > 0: w = width * v / tot; o.append(f'<rect x="{x:.1f}" width="{w:.1f}" height="{height}" fill="{col}"/>'); x += w
    return "".join(o) + "</g></svg>"
