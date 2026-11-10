"""The generated coverage pages must match the knowledge base and must not overclaim."""
import os, re, sys, tempfile, unittest, xml.dom.minidom
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools", "kb"))
import build_coverage

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


class Coverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp(); cls.n = build_coverage.build(ROOT, cls.out)
        with open(os.path.join(cls.out, "README.md"), encoding="utf-8") as fh: cls.text = fh.read()

    def test_numbers_match_the_knowledge_base(self):
        checks, _ = build_coverage.load(ROOT)
        self.assertEqual(self.n["checks"], len(checks))
        self.assertIn(f"**{len(checks)}** in **{self.n['pillars']}** pillars", self.text)
        self.assertEqual(self.n["auto"], sum(c["automated"] == "yes" for c in checks))

    def test_every_pillar_has_a_page_and_every_check_is_listed(self):
        checks, _ = build_coverage.load(ROOT)
        for c in checks:
            with open(os.path.join(self.out, "pillars", c["pillar"] + ".md"), encoding="utf-8") as fh: self.assertIn(f"[{c['id']}]", fh.read())

    def test_it_says_plainly_that_zero_days_are_not_scanned_and_that_this_is_alpha(self):
        self.assertIn("Do you scan for zero-days? No.", self.text); self.assertIn("Alpha", self.text)
        self.assertRegex(self.text, r"Zero-day vulnerabilities \| No\.")

    def test_graphics_are_valid_svg(self):
        for f in ("overview.svg", "targets.svg", "how-it-works.svg", "pillars.svg", "by-pillar.svg", "social-preview.svg"): xml.dom.minidom.parse(os.path.join(self.out, f))

    def test_committed_pages_are_current(self):
        with open(os.path.join(ROOT, "docs", "coverage", "README.md"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), self.text, "run: python3 tools/kb/build_coverage.py")


if __name__ == "__main__": unittest.main()
