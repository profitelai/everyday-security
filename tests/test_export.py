"""Tests for the two exports: the JSON fix pack for an AI assistant and the print-ready report behind the PDF."""
import json, os, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from everyday import export, pdf, report

def _run(kb=None):
    res = [{"id": "TLS-001", "status": "FAIL", "severity": "high", "pillar": "tls", "title": "Only TLS 1.2 and TLS 1.3", "detail": "accepts TLS 1.0", "kb": kb, "evidence": {"a": 1}, "confidence": "high"},
           {"id": "HDR-001", "status": "PASS", "severity": "high", "pillar": "http-headers", "title": "HSTS", "detail": "ok", "kb": None},
           {"id": "HDR-002", "status": "WARN", "severity": "high", "pillar": "http-headers", "title": "CSP", "detail": "weak", "kb": None}]
    return {"version": "v", "pack_hash": "h", "rules_loaded": 0, "started": "2026-01-01T00:00:00", "finished": "x", "deep": False,
            "sites": [{"host": "a.com", "name": "a", "tags": [], "score": 80, "grade": "B", "tally": {"FAIL": 1, "WARN": 1, "PASS": 1}, "rules": {}, "seconds": 1, "results": res}]}

class FixPack(unittest.TestCase):
    def test_lists_only_what_needs_attention_worst_first_with_assistant_rules(self):
        p = export.fix_pack(_run(), "r1")
        self.assertEqual(p["schema"], export.SCHEMA); self.assertEqual(p["tool"]["maturity"], "alpha")
        f = p["sites"][0]["findings"]; self.assertEqual([x["id"] for x in f], ["TLS-001", "HDR-002"]); self.assertEqual(f[0]["priority"], 1)
        self.assertTrue(any("ask" in i.lower() for i in p["instructions_for_assistant"])); self.assertTrue(any("wrong" in i.lower() for i in p["instructions_for_assistant"]))
    def test_includes_fix_and_rollback_text_from_the_knowledge_base(self):
        root = os.path.join(os.path.dirname(__file__), ".."); kb = [os.path.relpath(os.path.join(d, n), root) for d, _, fs in os.walk(os.path.join(root, "kb", "tls")) for n in fs if n.startswith("TLS-001")][0]
        f = export.fix_pack(_run(kb), "r1")["sites"][0]["findings"][0]
        for k in ("why_it_matters", "how_to_test", "pass_criteria", "fix", "risk_and_rollback"): self.assertTrue(f.get(k), k)
        self.assertEqual(f["evidence"], {"a": 1})
    def test_written_file_is_valid_json_and_nothing_is_uploaded(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("socket.socket", side_effect=AssertionError("network used")):
            path = export.write_fix_pack(_run(), "r1", d)
            with open(path, encoding="utf-8") as f: self.assertEqual(json.load(f)["run"]["id"], "r1")

class PrintableReport(unittest.TestCase):
    def test_print_report_has_logo_footer_and_alpha_note(self):
        h = report.to_html(_run(), "r1", pdf=True)
        self.assertIn("@bottom-left", h); self.assertIn("Profitell Security Consulting", h); self.assertIn("data:image/svg+xml", h); self.assertIn("Alpha", h); self.assertIn("class='mini'", h)
    def test_screen_report_keeps_collapsible_list(self):
        self.assertIn("<details><summary>", report.to_html(_run(), "r1"))

class Browser(unittest.TestCase):
    def test_no_browser_means_no_pdf_not_a_crash(self):
        with mock.patch.object(pdf, "find_browser", return_value=None): self.assertIsNone(pdf.html_to_pdf("x.html", "x.pdf"))
    def test_env_override(self):
        self.assertIsNone(pdf.find_browser({"EVERYDAY_BROWSER": "/no/such/browser"}))

if __name__ == "__main__": unittest.main()
