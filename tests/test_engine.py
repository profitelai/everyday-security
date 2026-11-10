import http.server, json, os, sys, tempfile, threading, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from everyday import ingest, registry, report, rules, store
from everyday.model import score, tally

class FakeCtx:
    def __init__(self, headers=None, host="127.0.0.1", port=None, deep=True):
        self.host = host; self.apex = host; self.deep = deep; self.timeout = 3; self.has_dig = False; self.subdomains = []; self._h = headers or {}; self.port = port
    def main(self): return {"status": 200, "headers": {k.lower(): v for k, v in self._h.items()}, "cookies": [], "body": b""}

def rule(**k):
    r = {"id": "HDR-R-9001", "type": "http_header", "title": "t", "severity": "low", "source": "https://example.com", "license": "x", "added": "2026-01-01", "status": "approved", "header": "X-Test", "expect": "present"}; r.update(k); return r

class Scoring(unittest.TestCase):
    def test_score_and_grade(self):
        self.assertEqual(score([]), (100, "A"))
        s, g = score([{"status": "FAIL", "severity": "high"}, {"status": "WARN", "severity": "medium"}]); self.assertEqual(s, 100 - 12 - 3); self.assertEqual(g, "B")
        self.assertEqual(score([{"status": "MANUAL", "severity": "critical"}, {"status": "PASS", "severity": "critical"}])[0], 100)
    def test_tally(self): self.assertEqual(tally([{"status": "PASS"}, {"status": "FAIL"}])["FAIL"], 1)

class Validation(unittest.TestCase):
    def test_valid(self): self.assertEqual(registry.validate_rule(rule()), [])
    def test_bad_fields(self):
        e = registry.validate_rule(rule(severity="huge", status="maybe", added="today", expect="equals")); self.assertTrue(any("severity" in x for x in e) and any("status" in x for x in e) and any("added" in x for x in e) and any("value required" in x for x in e))
    def test_unknown_type(self): self.assertTrue(registry.validate_rule({"type": "nope"}))
    def test_id_prefix(self): self.assertTrue(any("id must start" in x for x in registry.validate_rule(rule(id="PRB-0001"))))
    def test_regex_checked(self): self.assertTrue(any("regex" in x for x in registry.validate_rule(rule(expect="regex", value="("))))
    def test_shipped_packs_are_valid(self):
        _, probs = registry.load_packs(include_pending=True); self.assertEqual(probs, [])
    def test_every_automated_check_has_a_runner(self):
        from everyday.runners import provided_ids
        miss = [i for i, c in registry.load_checks().items() if c["automated"] == "yes" and i not in provided_ids()]; self.assertEqual(miss, [])

class HeaderAndBanner(unittest.TestCase):
    def test_absent_rule_hits(self): self.assertIsNotNone(rules.eval_http_header(FakeCtx({"X-Powered-By": "PHP/7.4.1"}), rule(header="X-Powered-By", expect="absent")))
    def test_absent_rule_clean(self): self.assertFalse(rules.eval_http_header(FakeCtx({}), rule(header="X-Powered-By", expect="absent")))
    def test_not_regex(self):
        self.assertTrue(rules.eval_http_header(FakeCtx({"X-XSS-Protection": "1; mode=block"}), rule(header="X-XSS-Protection", expect="not_regex", value=r"^\s*1")))
        self.assertFalse(rules.eval_http_header(FakeCtx({"X-XSS-Protection": "0"}), rule(header="X-XSS-Protection", expect="not_regex", value=r"^\s*1")))
    def test_version_compare(self):
        r = rule(id="VER-0001", type="banner_version", header="Server", regex=r"Apache/(\d+\.\d+(?:\.\d+)?)", bad_below="2.4.0")
        self.assertTrue(rules.eval_banner_version(FakeCtx({"Server": "Apache/2.2.34"}), r)); self.assertFalse(rules.eval_banner_version(FakeCtx({"Server": "Apache/2.4.58"}), r)); self.assertFalse(rules.eval_banner_version(FakeCtx({"Server": "nginx"}), r))
    def test_expired_rule_skipped(self):
        f, st = rules.run_rules(FakeCtx({"X-Powered-By": "x"}), [rule(header="X-Powered-By", expect="absent", expires="2020-01-01")], "2026-11-09"); self.assertEqual((f, st["expired"]), ([], 1))

class Probing(unittest.TestCase):
    """Path probes must not report hits on a site that answers 200 to everything, and must catch a real exposure."""
    @classmethod
    def setUpClass(cls):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                body = b"<html>welcome</html>" if cls.mode == "catchall" else (b"APP_KEY=abc123\nDB_PASSWORD=x\n" if self.path == "/.env" else b"nope")
                self.send_response(200 if cls.mode == "catchall" or self.path == "/.env" else 404); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), H); cls.port = cls.srv.server_address[1]; threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()
    def probe(self, mode, **k):
        Probing.mode = mode; import everyday.rules as R, everyday.context as C
        orig = C.fetch
        def local_fetch(host, port=443, path="/", headers=None, timeout=10, limit=65536): return orig("127.0.0.1", self.port, path, headers, timeout, limit) if False else _fetch_http(self.port, path, limit)
        R.fetch = local_fetch
        try: return R.PathProber(FakeCtx())(FakeCtx(), rule(id="PRB-0001", type="path_probe", path="/.env", expect_status=[200], **k))
        finally: R.fetch = orig
    def test_real_exposure_found(self): self.assertTrue(self.probe("normal", body_regex=r"(?m)^[A-Z][A-Z0-9_]{2,}="))
    def test_catch_all_site_not_flagged(self): self.assertFalse(self.probe("catchall"))
    def test_catch_all_with_signature_not_flagged(self): self.assertFalse(self.probe("catchall", body_regex=r"(?m)^[A-Z][A-Z0-9_]{2,}="))

def _fetch_http(port, path, limit):
    import http.client; c = http.client.HTTPConnection("127.0.0.1", port, timeout=3); c.request("GET", path); r = c.getresponse(); b = r.read(limit); c.close()
    return {"status": r.status, "headers": {}, "cookies": [], "body": b}

class Ingest(unittest.TestCase):
    def setUp(self): self.d = tempfile.mkdtemp(); [os.makedirs(os.path.join(self.d, p)) for p in ("data/packs", "data/incoming", "kb", "docs")]
    def test_ingest_dedupe_approve(self):
        rows = [{"path": "/secret.txt", "severity": "high", "title": "Secret file", "body_regex": "SECRET"}, {"path": "/secret.txt", "severity": "high", "title": "dup"}, {"path": "no-slash", "title": "bad"}]
        res = ingest.ingest_rules("path_probe", rows, "https://example.com", "own", "tester", root=self.d, stamp="t1")
        self.assertEqual((res["added"], res["duplicates"], res["invalid"]), (1, 1, 1))
        again = ingest.ingest_rules("path_probe", [rows[0]], "https://example.com", "own", "tester", root=self.d, stamp="t2"); self.assertEqual((again["added"], again["duplicates"]), (0, 1))
        dst, n = ingest.approve(res["file"], "reviewer", root=self.d); self.assertEqual(n, 1); self.assertFalse(os.path.exists(res["file"]))
        r = json.load(open(dst))["rules"][0]; self.assertEqual((r["status"], r["reviewed_by"], r["id"]), ("approved", "reviewer", "PRB-0001"))
    def test_ids_continue(self):
        ingest.ingest_rules("takeover", [{"cname_suffix": "a.example", "fingerprint": "x"}], "https://example.com", "own", "t", root=self.d, stamp="a")
        r = ingest.ingest_rules("takeover", [{"cname_suffix": "b.example", "fingerprint": "y"}], "https://example.com", "own", "t", root=self.d, stamp="b")
        self.assertEqual(json.load(open(r["file"]))["rules"][0]["id"], "TKO-0002")
    def test_check_ingest_requires_known_sources(self):
        row = dict(id="ABC-001", pillar="demo", title="T", severity="low", sources="S-NOPE", tags="a|b", target="website", method="manual-review", tool="browser", why="w", test="t", **{"pass": "p"}, fix="f", risk="r")
        self.assertEqual(ingest.ingest_checks([row], root=self.d)["invalid"], 1)

class Store(unittest.TestCase):
    def test_diff(self):
        db = os.path.join(tempfile.mkdtemp(), "h.db")
        def run(findings): return {"started": "s", "finished": "f", "version": "v", "pack_hash": "h", "deep": False, "sites": [{"host": "a.com", "score": 90, "grade": "A", "results": [{"id": i, "status": "FAIL", "severity": "high", "pillar": "p", "title": "t", "detail": "d"} for i in findings]}]}
        store.save(run(["X-1", "X-2"]), "20260101-000001", db); store.save(run(["X-2", "X-3"]), "20260102-000001", db)
        d = store.diff("20260102-000001", store.previous_run("20260102-000001", db), db); self.assertEqual(([x["id"] for x in d["new"]], [x["id"] for x in d["resolved"]]), (["X-3"], ["X-1"]))

class Reports(unittest.TestCase):
    def test_html_escapes(self):
        run = {"version": "v", "pack_hash": "h", "rules_loaded": 0, "started": "2026-01-01T00:00:00", "deep": False, "sites": [{"host": "<script>x</script>.com", "name": "<b>n</b>", "tags": [], "score": 50, "grade": "F", "tally": {"FAIL": 1}, "rules": {}, "seconds": 1, "results": [{"id": "A-1", "status": "FAIL", "detail": "<img src=x onerror=1>", "severity": "high", "title": "t", "pillar": "p", "tags": []}]}]}
        h = report.to_html(run, "r1"); self.assertNotIn("<script>x", h); self.assertNotIn("<img src=x", h); self.assertIn("&lt;img", h)

if __name__ == "__main__": unittest.main()
