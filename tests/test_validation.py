"""Validation tests: the INCONCLUSIVE status, recorded evidence, and the permanent MAIL-007 regression case."""
import json, os, sqlite3, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from everyday import engine, model, report, store
from everyday.runners import outside

# Recorded facts from the real investigation of facilinvoice.ca (read-only, own domain, 2026-11-09):
# the only MX host presents a valid Let's Encrypt chain for other names, TLS 1.2, valid for 31 more days.
# The scanner once reported this as one confusing error string (and first as a FAIL). It must stay a WARN
# that says what is true on each of the three questions: chain, name, expiry.
FACILINVOICE = {"host": "_dc-mx.829f523f152a.facilinvoice.ca", "port": 25, "reachable": True, "starttls": True, "chain": "trusted",
                "tls_version": "TLSv1.2", "names": ["mail.bizlocal.ca", "mail.danimaster.com"], "name_matches": False,
                "issuer": "Let's Encrypt, YE1", "not_after": "Dec 10 00:00:00 2026 GMT", "days_left": 31}
NO_POLICY = {"mta_sts": None, "dane": False}


class Mail007Regression(unittest.TestCase):
    def test_recorded_case_is_a_warning_not_a_failure(self):
        st, detail, extra = outside.judge_mx_tls([dict(FACILINVOICE)], NO_POLICY)
        self.assertEqual(st, "WARN")
        self.assertIn("name does not match", detail)
        self.assertIn("mail.danimaster.com", detail)          # says what the certificate is for
        self.assertNotIn("does not validate", detail)         # the old merged error string must not return
        self.assertEqual(extra["confidence"], "medium")
        self.assertEqual(extra["evidence"]["hosts"][0]["days_left"], 31)

    def test_same_case_fails_only_when_senders_will_enforce_the_name(self):
        for policy in ({"mta_sts": "enforce", "dane": False}, {"mta_sts": None, "dane": True}):
            st, detail, extra = outside.judge_mx_tls([dict(FACILINVOICE)], policy)
            self.assertEqual(st, "FAIL"); self.assertEqual(extra["confidence"], "high"); self.assertIn("refuse delivery", detail)
        self.assertEqual(outside.judge_mx_tls([dict(FACILINVOICE)], {"mta_sts": "testing", "dane": False})[0], "WARN")

    def test_matching_name_and_healthy_certificate_passes(self):
        ok = dict(FACILINVOICE, name_matches=True, names=[FACILINVOICE["host"]])
        st, detail, _ = outside.judge_mx_tls([ok], NO_POLICY)
        self.assertEqual(st, "PASS"); self.assertIn("chain trusted", detail); self.assertIn("31 more days", detail)

    def test_blocked_port_25_is_inconclusive_not_a_verdict(self):
        st, detail, extra = outside.judge_mx_tls([{"host": "mx.example.com", "port": 25, "reachable": False, "error": "TimeoutError"}], NO_POLICY)
        self.assertEqual(st, "INCONCLUSIVE"); self.assertEqual(extra["confidence"], "low"); self.assertIn("could not be reached", detail)

    def test_clear_failures_stay_failures(self):
        cases = {"does not offer STARTTLS": {"starttls": False}, "expired": {"chain": "untrusted", "verify_code": 10, "chain_error": "certificate has expired"},
                 "TLSv1.1": {"tls_version": "TLSv1.1", "name_matches": True}}
        for text, change in cases.items():
            st, detail, _ = outside.judge_mx_tls([dict(FACILINVOICE, **change)], NO_POLICY)
            self.assertEqual(st, "FAIL", text); self.assertIn(text, detail)

    def test_untrusted_chain_and_near_expiry_are_warnings(self):
        self.assertEqual(outside.judge_mx_tls([dict(FACILINVOICE, chain="untrusted", verify_code=20, chain_error="unable to get local issuer certificate")], NO_POLICY)[0], "WARN")
        st, detail, _ = outside.judge_mx_tls([dict(FACILINVOICE, name_matches=True, days_left=5)], NO_POLICY)
        self.assertEqual(st, "WARN"); self.assertIn("expires in 5 days", detail)

    def test_handshake_error_is_inconclusive(self):
        st, _, _ = outside.judge_mx_tls([dict(FACILINVOICE, chain="error", error="SSLError")], NO_POLICY)
        self.assertEqual(st, "INCONCLUSIVE")


class NameMatching(unittest.TestCase):
    def test_exact_case_insensitive_and_trailing_dot(self):
        self.assertTrue(outside.name_matches("MX.Example.com.", ["mx.example.com"]))

    def test_wildcard_covers_one_label_only(self):
        self.assertTrue(outside.name_matches("mx.example.com", ["*.example.com"]))
        self.assertFalse(outside.name_matches("a.mx.example.com", ["*.example.com"]))
        self.assertFalse(outside.name_matches("example.com", ["*.example.com"]))

    def test_common_name_is_used_only_without_alt_names(self):
        self.assertEqual(outside.cert_names({"subject": ((("commonName", "cn.example.com"),),), "subjectAltName": (("DNS", "san.example.com"),)}), ["san.example.com"])
        self.assertEqual(outside.cert_names({"subject": ((("commonName", "cn.example.com"),),)}), ["cn.example.com"])


def _run(results):
    return {"version": "v", "pack_hash": "h", "rules_loaded": 0, "started": "2026-01-01T00:00:00", "finished": "2026-01-01T00:01:00", "deep": False,
            "sites": [{"host": "a.com", "name": "a", "tags": [], "score": 90, "grade": "A", "tally": model.tally(results), "rules": {}, "seconds": 1, "results": results}]}

def _res(**k):
    base = {"id": "MAIL-007", "status": "WARN", "severity": "medium", "pillar": "mail-authentication", "title": "t", "detail": "d", "kb": None}
    base.update(k); return base


class StatusAndEvidence(unittest.TestCase):
    def test_inconclusive_is_a_status_and_costs_nothing(self):
        self.assertIn("INCONCLUSIVE", model.STATUSES)
        self.assertEqual(model.score([_res(status="INCONCLUSIVE", severity="critical")])[0], 100)
        self.assertEqual(model.tally([_res(status="INCONCLUSIVE")])["INCONCLUSIVE"], 1)

    def test_engine_passes_evidence_and_confidence_through(self):
        runner = ("t", ["MAIL-007"], lambda ctx: [("MAIL-007", "INCONCLUSIVE", "no data", {"evidence": {"asked": "mx"}, "confidence": "low"}), ("HDR-001", "PASS", "ok")])
        with mock.patch("everyday.engine.load_all", return_value=[runner]):
            out = engine.scan_site({"host": "example.com"}, {}, None)["results"]
        self.assertEqual((out[0]["evidence"], out[0]["confidence"]), ({"asked": "mx"}, "low"))
        self.assertIsNone(out[1]["evidence"])

    def test_evidence_is_stored_and_old_databases_are_upgraded(self):
        db = os.path.join(tempfile.mkdtemp(), "h.db")
        old = sqlite3.connect(db)      # a database created before evidence existed
        old.executescript("CREATE TABLE results(run_id TEXT, host TEXT, check_id TEXT, status TEXT, severity TEXT, pillar TEXT, title TEXT, detail TEXT);")
        old.execute("INSERT INTO results VALUES ('old','a.com','X-1','WARN','low','p','t','d')"); old.commit(); old.close()
        store.save(_run([_res(evidence={"n": 1}, confidence="high")]), "20260101-000001", db)
        c = sqlite3.connect(db)
        self.assertEqual(json.loads(c.execute("SELECT evidence FROM results WHERE run_id='20260101-000001'").fetchone()[0]), {"n": 1})
        self.assertEqual(c.execute("SELECT confidence FROM results WHERE run_id='20260101-000001'").fetchone()[0], "high")
        self.assertEqual(c.execute("SELECT evidence FROM results WHERE run_id='old'").fetchone()[0], None)    # old rows stay readable
        c.close()

    def test_reports_show_inconclusive_and_escape_evidence(self):
        run = _run([_res(status="INCONCLUSIVE", evidence={"note": "<img src=x onerror=1>"}, confidence="low")])
        h = report.to_html(run, "r1")
        self.assertIn("inconclusive", h.lower()); self.assertIn("confidence: low", h); self.assertNotIn("<img src=x", h)
        self.assertIn("INCONCLUSIVE", report.to_markdown(run, "r1"))
        self.assertIn("confidence", report.to_csv(run).splitlines()[0])


if __name__ == "__main__": unittest.main()
