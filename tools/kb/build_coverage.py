#!/usr/bin/env python3
"""Generate docs/coverage/ (what Everyday Security can and cannot scan) from kb/ and data/packs/, so every number matches the content.
usage: python3 tools/kb/build_coverage.py"""
import collections, glob, json, os, re, sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage_art as art  # noqa: E402
from everyday import VERSION  # noqa: E402

PILLARS = {  # pillar -> (title, what it covers, who it is for)
    "tls": ("TLS and certificates", "HTTPS certificates, expiry, protocol versions, ciphers, redirects from HTTP.", "Any website"),
    "http-headers": ("HTTP security headers", "HSTS, CSP, frame protection, cookies, CORS, caching of private pages, version disclosure.", "Any website or web app"),
    "mail-authentication": ("Email authentication and transport", "SPF, DKIM, DMARC, MTA-STS, MX encryption (STARTTLS), reverse DNS.", "Any domain that sends or receives mail"),
    "dns": ("DNS hygiene", "Zone transfers, dangling records, private addresses in public DNS, DNSSEC, expiry of names.", "Any domain"),
    "web-app": ("Web application safeguards", "Login, sessions, uploads, injection, access control and error handling (review-based).", "Sites and apps you build or run"),
    "wordpress-and-cms": ("WordPress and CMS", "Updates, plugins, admin exposure, XML-RPC and REST user listing, backups, form spam.", "WordPress, Drupal, Joomla and similar sites"),
    "server-hardening": ("Server hardening", "SSH, firewall, listening ports, patching, fail2ban, clock, file permissions, certificate renewal.", "Linux servers you administer"),
    "containers": ("Containers and Docker", "Image sources and tags, scanning, privileges, published ports, secrets, resource limits.", "Docker and Compose hosts"),
    "backups-and-recovery": ("Backups and recovery", "3-2-1 copies, offsite and immutable copies, restore tests, retention, database dumps.", "Any business running systems"),
    "incident-response": ("Incident response", "Plan, owners, contacts, evidence, logging, communication, recovery and post-incident review.", "Any business"),
    "cloud-and-saas-accounts": ("Cloud and SaaS accounts", "Admin accounts, MFA, OAuth grants, public storage, offboarding, account inventory.", "Teams using Google, Microsoft, AWS and similar"),
    "vendor-and-supply-chain": ("Vendors and supply chain", "Vendor inventory and contracts, dependencies, CI/CD pipelines, third-party scripts, exit plans.", "Any business and any developer"),
    "privacy-compliance": ("Privacy practices", "Policy, consent, data inventory, retention, incident register, access requests. Informational, not legal advice.", "Businesses holding personal information"),
}
TARGETS = [  # what you can point it at
    ("Website or web app", "Public HTTPS and HTTP pages", "Automatic outside scan", "tls, http-headers, web-app, dns"),
    ("Email domain", "DNS records and the mail servers' port 25", "Automatic outside scan", "mail-authentication, dns"),
    ("Whole domain and its subdomains", "DNS, certificates, takeover fingerprints", "Automatic outside scan (fleet)", "dns, tls"),
    ("Linux server", "Local configuration, read-only", "Server audit run on the server", "server-hardening"),
    ("WordPress or other CMS site", "Public paths plus a checklist", "Outside scan and guided checklist", "wordpress-and-cms"),
    ("Docker host", "Published ports plus a checklist", "Server audit and guided checklist", "containers"),
    ("Cloud and SaaS accounts", "Your admin consoles", "Guided checklist (human)", "cloud-and-saas-accounts"),
    ("Business processes", "Backups, incidents, vendors", "Guided checklist (human)", "backups-and-recovery, incident-response, vendor-and-supply-chain, privacy-compliance"),
]
NOT_DONE = [
    ("Zero-day vulnerabilities", "No. We do not hunt unknown flaws and we do not use a live exploit or CVE feed."),
    ("Known CVEs in installed software", "Not by matching a vulnerability database. A short, hand-written list of end-of-life versions is checked when a server announces its version. Use a dedicated tool such as Trivy for CVEs (the checks explain how)."),
    ("Exploitation and penetration testing", "No. Nothing is exploited, no payloads are sent, no passwords or logins are tried."),
    ("Port scanning of ranges", "No. Only ports 80 and 443 of the site, port 25 of its mail servers, and DNS queries (including a zone-transfer request to its name servers) are used."),
    ("Logged-in application testing", "No. Only what an anonymous visitor can see."),
    ("Malware or intrusion detection", "No."),
    ("Load or denial-of-service testing", "No."),
    ("Compliance certification", "No. Checks cite standards; passing them does not certify anything."),
]
SEV = ["critical", "high", "medium", "low", "info"]
METHOD = {"yes": "Automatic outside scan", "host": "Server audit", "no": "Guided checklist"}
FAMILIES = [("OWASP", r"OWASP"), ("NIST", r"NIST"), ("IETF RFCs", r"RFC \d+"), ("CIS", r"CIS"), ("W3C / WHATWG", r"CSP|W3C|Fetch Standard|Permissions"),
            ("Canadian Centre for Cyber Security", r"Cyber Centre"), ("Privacy law (informational)", r"Law 25|PIPEDA|GDPR"), ("Audit frameworks", r"SOC 2|ISO")]


def parse(path):
    t = open(path, encoding="utf-8").read(); m = re.match(r"---\n(.*?)\n---\n", t, re.S); fm = {}
    for l in m.group(1).splitlines():
        if ": " in l:
            k, v = l.split(": ", 1); v = v.strip()
            fm[k] = [x.strip().strip('"') for x in v[1:-1].split(",") if x.strip()] if v.startswith("[") else v.strip('"')
    return fm


def load(root):
    checks = []
    for p in sorted(glob.glob(os.path.join(root, "kb", "*", "*.md"))):
        if p.endswith("INDEX.md"): continue
        fm = parse(p); fm["path"] = os.path.relpath(p, root); checks.append(fm)
    rules = collections.Counter()
    for f in glob.glob(os.path.join(root, "data", "packs", "*.json")):
        for r in json.load(open(f, encoding="utf-8"))["rules"]: rules[r["type"]] += 1
    return checks, rules


def standards_by_family(checks):
    fam = collections.defaultdict(set)
    for c in checks:
        for s in c.get("standards", []):
            for name, rx in FAMILIES:
                if re.search(rx, s): fam[name].add(c["id"])
    return fam


def build(root=ROOT, out=None):
    out = out or os.path.join(root, "docs", "coverage"); os.makedirs(os.path.join(out, "pillars"), exist_ok=True)
    checks, rules = load(root); P = sorted({c["pillar"] for c in checks}); by = {p: [c for c in checks if c["pillar"] == p] for p in P}
    auto = sum(c["automated"] == "yes" for c in checks); host = sum(c["automated"] == "host" for c in checks); manual = len(checks) - auto - host
    sev = collections.Counter(c["severity"] for c in checks); fam = standards_by_family(checks)
    sources = len({i for f in glob.glob(os.path.join(root, "docs", "sources*.md")) + glob.glob(os.path.join(root, "docs", "sources.d", "*.md")) for i in re.findall(r"^\| (S-[A-Z0-9\-]+) \|", open(f, encoding="utf-8").read(), re.M)})
    n = {"checks": len(checks), "pillars": len(P), "auto": auto, "host": host, "rules": sum(rules.values()), "sources": sources}
    rows = [(PILLARS[p][0], sum(c["automated"] == "yes" for c in by[p]), sum(c["automated"] == "host" for c in by[p]), sum(c["automated"] == "no" for c in by[p])) for p in P]
    rows.sort(key=lambda r: -(r[1] + r[2] + r[3]))
    def count(*ps): return sum(len(by.get(p, [])) for p in ps)
    tgt = [("globe", "Website or web app", "Public HTTPS pages", count("tls", "http-headers", "web-app"), [("OUTSIDE SCAN", art.AUTO), ("CHECKLIST", "#6b7280")]),
           ("page", "WordPress and CMS", "WordPress, Drupal, Joomla", count("wordpress-and-cms"), [("OUTSIDE SCAN", art.AUTO), ("CHECKLIST", "#6b7280")]),
           ("mail", "Email domain", "SPF, DKIM, DMARC, MX TLS", count("mail-authentication"), [("OUTSIDE SCAN", art.AUTO)]),
           ("network", "DNS and subdomains", "Zones, takeover, DNSSEC", count("dns"), [("OUTSIDE SCAN", art.AUTO)]),
           ("server", "Linux server", "SSH, firewall, patching", count("server-hardening"), [("SERVER AUDIT", art.INK), ("CHECKLIST", "#6b7280")]),
           ("cube", "Docker host", "Images, ports, privileges", count("containers"), [("SERVER AUDIT", art.INK), ("CHECKLIST", "#6b7280")]),
           ("cloud", "Cloud and SaaS", "Google, Microsoft, AWS", count("cloud-and-saas-accounts"), [("CHECKLIST", "#6b7280")]),
           ("people", "Business processes", "Backups, incidents, vendors", count("backups-and-recovery", "incident-response", "vendor-and-supply-chain", "privacy-compliance"), [("CHECKLIST", "#6b7280")])]
    cards = [(art.PILLAR_ICON[p], PILLARS[p][0], len(by[p]), sum(c["automated"] == "yes" for c in by[p]), sum(c["automated"] == "host" for c in by[p]), sum(c["automated"] == "no" for c in by[p])) for p in sorted(P, key=lambda p: -len(by[p]))]
    for name, text in (("overview.svg", art.overview(n, VERSION)), ("targets.svg", art.targets(tgt)), ("how-it-works.svg", art.how_it_works(n)), ("pillars.svg", art.pillars(cards)), ("by-pillar.svg", art.by_pillar(rows)), ("social-preview.svg", art.social(n, VERSION))):
        open(os.path.join(out, name), "w", encoding="utf-8").write(text)
    L = [f"# What Everyday Security can scan", "", "![Coverage at a glance](overview.svg)", "", "![What you can point it at](targets.svg)", "",
         f"> **Status: Alpha ({VERSION}).** The checks are drafts written from cited public sources and have not yet been reviewed by a named human security professional or measured against known-good and known-bad systems. A finding can be wrong, and a clean result is not proof of safety. Only scan systems you own or have written permission to test. This page is generated from the repository by `tools/kb/build_coverage.py`, so the numbers always match the content.", "",
         "## At a glance", "", "| | |", "|---|---:|", f"| Security checks | **{n['checks']}** in **{n['pillars']}** pillars |",
         f"| Run automatically against a website or domain | **{auto}** |", f"| Run by the read-only server audit (on the server itself) | **{host}** |", f"| Guided checklists for a person (not automatable from outside) | **{manual}** |",
         f"| Data-driven scan rules | **{n['rules']}** ({', '.join(f'{v} {k.replace(chr(95), chr(32))}' for k, v in sorted(rules.items(), key=lambda x: -x[1]))}) |",
         f"| Severity | " + " · ".join(f"{sev[s]} {s}" for s in SEV if sev[s]) + " |", f"| Public sources cited | **{sources}** |", "",
         "![How a scan works](how-it-works.svg)", "", "![The 13 pillars](pillars.svg)", "", "![Checks per pillar](by-pillar.svg)", "", "## What can I point it at?", "", "| Target | What is examined | How | Pillars |", "|---|---|---|---|"]
    L += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in TARGETS]
    L += ["", "## How a check is run", "", "| Method | Count | What happens |", "|---|---:|---|",
          f"| Automatic outside scan | {auto} | Ordinary web requests, TLS handshakes, DNS lookups, and a look at the domain's mail servers. Plus {n['rules']} data rules: sensitive paths, headers, end-of-life versions, takeover fingerprints, DNS expectations. |",
          f"| Server audit | {host} | `audit-host` reads local configuration on a Linux server (SSH, firewall, ports, Docker, updates, fail2ban, clock, permissions, certificate renewal). Read-only, no network calls. |",
          f"| Guided checklist | {manual} | Each check explains why it matters, how to test it by hand, the pass criteria, the fix and the rollback. A person confirms the answer. |", "",
          "## Do you scan for zero-days? No.", "",
          "Everyday Security is a **configuration and exposure checker**, not a vulnerability hunter. It looks for well-known, documented weaknesses that small businesses commonly have. It does not discover unknown flaws.", "",
          "| Question | Answer |", "|---|---|"]
    L += [f"| {a} | {b} |" for a, b in NOT_DONE]
    L += ["", "## What the data rules look for", "", "| Rule type | Count | Example |", "|---|---:|---|"]
    ex = {"path_probe": "Is `/.env`, `/.git/HEAD` or a database dump downloadable?", "http_header": "Is a recommended security header missing?", "banner_version": "Does the server announce an end-of-life Apache or PHP version?",
          "takeover": "Does a subdomain point at an unclaimed GitHub Pages or Heroku app?", "dns_record": "Is DMARC still monitor-only? Does SPF allow every sender?"}
    L += [f"| {k.replace('_', ' ')} | {v} | {ex.get(k, '')} |" for k, v in sorted(rules.items(), key=lambda x: -x[1])]
    L += ["", "## Pillars", "", "| Pillar | What it covers | Checks | Auto | Server | Checklist | For |", "|---|---|---:|---:|---:|---:|---|"]
    for p in sorted(P, key=lambda p: -len(by[p])):
        t, d, who = PILLARS[p]; L.append(f"| [{t}](pillars/{p}.md) | {d} | {len(by[p])} | {sum(c['automated'] == 'yes' for c in by[p])} | {sum(c['automated'] == 'host' for c in by[p])} | {sum(c['automated'] == 'no' for c in by[p])} | {who} |")
    L += ["", "## Standards the checks reference", "", "Checks cite public standards and primary documentation. This is a reference list, not a claim of certification or full coverage of any framework.", "",
          "| Standards family | Checks that cite it |", "|---|---:|"] + [f"| {k} | {len(v)} |" for k, v in sorted(fam.items(), key=lambda x: -len(x[1]))]
    L += ["", "The complete list with links is in [`docs/sources.md`](../sources.md) and [`docs/sources.d/`](../sources.d/).", "",
          "## Maturity", "", "| Level | Meaning | |", "|---|---|---|", "| **Alpha (now)** | Fixture-tested logic; drafts; own systems only | current |", "| Beta | Benchmarked against known-good and known-bad systems, evidence in every finding | planned |",
          "| 1.0 | Independently reviewed and validated | planned |", "",
          "Every result is `PASS`, `WARN`, `FAIL`, `INCONCLUSIVE` (not enough evidence) or `MANUAL` (needs a person), and can carry recorded evidence and a confidence level.", "",
          "## More", "", "- [All checks, one table](../../kb/INDEX.md)", "- [How the engine works](../ARCHITECTURE.md)", "- [Where the content comes from](../PROVENANCE.md)", "- [Review queue: what is still unverified](../REVIEW-QUEUE.md)", "- [Automation roadmap: why not every check runs by itself](../AUTOMATION-ROADMAP.md)", "- [Back to the project README](../../README.md)", "",
          "## Disclaimer", "", "Provided for information only, as is, without warranty. Not legal, privacy, compliance or professional security advice. See the Disclaimer in the project README.", ""]
    open(os.path.join(out, "README.md"), "w", encoding="utf-8").write("\n".join(L))
    for p in P:
        t, d, who = PILLARS[p]; M = [f"# {t}", "", f"[← Coverage](../README.md)", "", d, "", f"**{len(by[p])} checks** · {sum(c['automated'] == 'yes' for c in by[p])} run automatically · {sum(c['automated'] == 'host' for c in by[p])} in the server audit · {sum(c['automated'] == 'no' for c in by[p])} guided checklists · for: {who}", "",
                                     "| ID | Check | Severity | How it is run | Standards |", "|---|---|---|---|---|"]
        for c in sorted(by[p], key=lambda c: c["id"]):
            M.append(f"| [{c['id']}](../../{c['path']}) | {c['title']} | {c['severity']} | {METHOD[c['automated']]} | {', '.join(c.get('standards', [])) or '-'} |")
        M += ["", "All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.", ""]
        open(os.path.join(out, "pillars", f"{p}.md"), "w", encoding="utf-8").write("\n".join(M))
    return n


if __name__ == "__main__":
    n = build(); print(f"coverage written: {n['checks']} checks, {n['pillars']} pillars, {n['auto']} automatic, {n['host']} server audit, {n['rules']} rules")
