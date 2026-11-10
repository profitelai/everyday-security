"""Tests for the report visuals (rings, donut) and the 'where to fix' hints."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from everyday import charts, report, where

def _site(host, edge, results):
    from everyday.model import score, tally
    s, g = score(results); return {"host": host, "name": host, "edge": edge, "tags": [], "score": s, "grade": g, "tally": tally(results), "rules": {}, "seconds": 1, "results": results}
def _r(i, st, sv, pillar="tls"): return {"id": i, "status": st, "severity": sv, "pillar": pillar, "title": i + " title", "detail": "d", "kb": None}
def _run(sites): return {"version": "v", "pack_hash": "h", "rules_loaded": 0, "started": "2026-01-01T00:00:00", "finished": "x", "deep": False, "sites": sites}

class Charts(unittest.TestCase):
    def test_ring_is_valid_and_clamped(self):
        import xml.dom.minidom as m
        for v in (-5, 0, 78, 100, 250): m.parseString(charts.ring(v))
        self.assertIn("stroke-dasharray=\"0.00", charts.ring(0)); self.assertIn(">100<", charts.ring(250))
    def test_donut_ignores_zero_parts_and_is_valid(self):
        import xml.dom.minidom as m
        m.parseString(charts.donut([(0, "#000"), (3, "#f00"), (7, "#0f0")], big=10, small="x")); m.parseString(charts.donut([(0, "#000")]))

class Where(unittest.TestCase):
    def test_known_and_prefix_ids(self):
        self.assertEqual(where.where("TLS-001")[1], "yes"); self.assertEqual(where.where("DNR-0001")[1], "yes"); self.assertEqual(where.where("APP-002")[1], "no"); self.assertEqual(where.where("ZZZ-1"), ("", "no", ""))
    def test_summary_counts_only_open_findings(self):
        c = where.cloudflare_summary([_r("TLS-001", "FAIL", "high"), _r("HDR-002", "WARN", "high"), _r("APP-002", "FAIL", "critical"), _r("TLS-005", "PASS", "low")])
        self.assertEqual((c["yes"], c["partly"], c["no"], c["open"]), (1, 1, 1, 3))

class Html(unittest.TestCase):
    def test_hero_rings_and_cloudflare_scope(self):
        run = _run([_site("a.com", "cloudflare", [_r("TLS-001", "FAIL", "high")]), _site("b.com", None, [_r("TLS-005", "WARN", "low")])])
        h = report.to_html(run, "r1")
        self.assertIn('class="ring"', h); self.assertIn('class="donut"', h); self.assertIn("Overall score", h); self.assertIn("1 Cloudflare site", h); self.assertIn("Behind Cloudflare", h); self.assertIn("Served directly", h)
    def test_no_cloudflare_site_says_so_instead_of_claiming_fixes(self):
        h = report.to_html(_run([_site("b.com", None, [_r("TLS-005", "WARN", "low")])]), "r1"); self.assertIn("No scanned site is behind Cloudflare", h)
    def test_works_with_no_findings_and_in_pdf_mode(self):
        h = report.to_html(_run([_site("c.com", None, [_r("TLS-001", "PASS", "high")])]), "r1", pdf=True); self.assertIn("No problems found", h); self.assertIn("@bottom-left", h)

if __name__ == "__main__": unittest.main()
