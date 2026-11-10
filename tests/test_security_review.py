"""Tests for tools/scanner/security_review.py: the server review script (no network, no server access)."""
import email.message, importlib.util, os, sys, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("security_review", os.path.join(HERE, "..", "tools", "scanner", "security_review.py"))
sr = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(sr)


def fake_dig(table):
    return lambda name, rtype: table.get((name, rtype), [])


class Base(unittest.TestCase):
    def setUp(self): sr.F.clear()
    def checks(self): return {f.check: f for f in sr.F}


class Cookies(Base):
    def test_every_cookie_is_judged_and_named(self):
        got = dict(sr.cookie_issues("sid=1; Path=/; Secure; HttpOnly\nprefs=2; Path=/\ntrack=3; Secure"))
        self.assertEqual(got, {"prefs": ["Secure", "HttpOnly"], "track": ["HttpOnly"]})

    def test_cloudflare_cookies_and_empty_values_are_ignored(self):
        self.assertEqual(sr.cookie_issues("__cf_bm=1; Path=/\n_cfuvid=2"), [])
        self.assertEqual(sr.cookie_issues(""), [])

    def test_attribute_names_are_case_insensitive(self):
        self.assertEqual(sr.cookie_issues("sid=1; SECURE; httponly; SameSite=Lax"), [])

    def test_repeated_set_cookie_headers_are_all_kept(self):
        m = email.message.Message(); m["Set-Cookie"] = "a=1; Secure"; m["Set-Cookie"] = "b=2"; m["Server"] = "x"; m["Vary"] = "A"; m["Vary"] = "B"
        d = sr.header_dict(m)
        self.assertEqual(d["set-cookie"].split("\n"), ["a=1; Secure", "b=2"]); self.assertEqual(d["vary"], "A, B")


class DnsDangling(Base):
    def run_dns(self, table, rcode="NOERROR"):
        with mock.patch.object(sr, "dig", fake_dig(table)), mock.patch.object(sr, "dig_rcode", lambda n, t="A": rcode):
            sr.check_dns("app.example.com")
        return self.checks()

    def test_cname_that_resolves_to_addresses_is_not_dangling(self):
        got = self.run_dns({("app.example.com", "CNAME"): ["t.example.net."], ("app.example.com", "A"): ["t.example.net.", "203.0.113.5"]})
        self.assertFalse([k for k in got if k.startswith("dns-dangling") or k == "dns-cname-noaddr"])

    def test_cname_resolving_only_through_aaaa_is_not_dangling(self):
        got = self.run_dns({("app.example.com", "CNAME"): ["t.example.net."], ("app.example.com", "AAAA"): ["t.example.net.", "2001:db8::1"]})
        self.assertNotIn("dns-dangling", got)

    def test_cname_to_nonexistent_name_is_dangling(self):
        got = self.run_dns({("app.example.com", "CNAME"): ["gone.example.net."]}, rcode="NXDOMAIN")
        self.assertEqual(got["dns-dangling"].severity, "high")

    def test_empty_but_existing_target_is_informational(self):
        got = self.run_dns({("app.example.com", "CNAME"): ["empty.example.net."]}, rcode="NOERROR")
        self.assertNotIn("dns-dangling", got); self.assertEqual(got["dns-cname-noaddr"].severity, "info")

    def test_resolver_failure_is_low_confidence_not_a_finding_of_takeover(self):
        got = self.run_dns({("app.example.com", "CNAME"): ["x.example.net."]}, rcode="SERVFAIL")
        self.assertNotIn("dns-dangling", got); self.assertEqual(got["dns-dangling-unverified"].confidence, "low")


class MailDomain(Base):
    def run_mail(self, table):
        with mock.patch.object(sr, "dig", fake_dig(table)):
            return sr.check_mail_domain("example.com"), self.checks()

    def test_dkim_at_another_selector_counts(self):
        info, got = self.run_mail({("example.com", "MX"): ["10 mx.example.com."], ("example.com", "TXT"): ['"v=spf1 -all"'], ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:a@example.com"'],
                                   ("selector1._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=AAAA"']})
        self.assertEqual(info["dkim_selectors"], ["selector1"]); self.assertNotIn("mail-dkim", got)

    def test_no_dkim_found_is_low_confidence_info_not_a_defect(self):
        _, got = self.run_mail({("example.com", "MX"): ["10 mx.example.com."], ("example.com", "TXT"): ['"v=spf1 -all"'], ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:a@example.com"']})
        self.assertEqual((got["mail-dkim"].severity, got["mail-dkim"].confidence), ("info", "low"))

    def test_missing_spf_and_dmarc_are_low_when_the_domain_sends_no_mail(self):
        _, got = self.run_mail({})
        self.assertEqual((got["mail-spf"].severity, got["mail-dmarc"].severity), ("low", "low"))

    def test_missing_spf_and_dmarc_are_medium_when_the_domain_sends_mail(self):
        _, got = self.run_mail({("example.com", "MX"): ["10 mx.example.com."]})
        self.assertEqual((got["mail-spf"].severity, got["mail-dmarc"].severity), ("medium", "medium"))

    def test_monitor_only_dmarc_is_low(self):
        _, got = self.run_mail({("example.com", "TXT"): ['"v=spf1 -all"'], ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none; rua=mailto:a@example.com"']})
        self.assertEqual(got["mail-dmarc-none"].severity, "low")

    def test_plus_all_spf_stays_high(self):
        _, got = self.run_mail({("example.com", "TXT"): ['"v=spf1 +all"'], ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:a@example.com"']})
        self.assertEqual(got["mail-spf-all"].severity, "high")


class PublicBasis(Base):
    def test_standard_backed_checks_name_a_source_with_a_url(self):
        for key in ("dns-dangling", "tls-legacy", "hdr-hsts", "hdr-csp", "hdr-disclose-server", "cookie-flags", "path/.env", "listing/uploads/", "mail-spf", "mail-spf-all", "mail-dmarc-rua",
                    "mail-dkim", "ufw-off", "port-5432", "fail2ban", "apt-pending", "ssh-password"):
            label, url = sr.spec_for(key)
            self.assertTrue(url and url.startswith("https://"), key)

    def test_checks_without_a_standard_say_so(self):
        label, url = sr.spec_for("tls-expiry")
        self.assertIsNone(url); self.assertIn("Operational", label)

    def test_findings_carry_basis_and_confidence(self):
        sr.add("example.com", "low", "hdr-hsts", "t"); d = sr.F[0].d()
        self.assertEqual(d["confidence"], "high"); self.assertIn("RFC 6797", d["basis"]); self.assertTrue(d["basis_url"])


class FirewallInference(Base):
    def test_the_inference_note_tells_the_reader_to_confirm_from_outside(self):
        self.assertIn("confirm with a scan from outside", sr.INFERRED)

    def test_exposed_port_findings_are_capped_and_low_confidence(self):
        outputs = {("ufw", "status"): "Status: active\n3306/tcp ALLOW Anywhere\n5432 ALLOW Anywhere", ("ss", "-tlnpH"): "LISTEN 0 80 0.0.0.0:3306 0.0.0.0:* users:((\"mysqld\",pid=1,fd=1))\nLISTEN 0 80 0.0.0.0:8081 0.0.0.0:* users:((\"web\",pid=2,fd=1))"}
        def fake_sh(cmd, timeout=60): return outputs.get(tuple(cmd[:2]), outputs.get(tuple(cmd), ""))
        with mock.patch.object(sr, "sh", fake_sh), mock.patch("builtins.open", side_effect=OSError):
            sr.check_host()
        got = self.checks()
        self.assertIn("port-3306", got); self.assertEqual(got["port-3306"].severity, "high")     # database port: high at most, never critical
        self.assertEqual(got["port-3306"].confidence, "low"); self.assertIn("confirm with a scan from outside", got["port-3306"].detail)
        self.assertNotIn("critical", {f.severity for f in sr.F if f.check.startswith("port-")})


if __name__ == "__main__": unittest.main()
