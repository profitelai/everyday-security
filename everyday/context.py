"""Per-site scan context: cached HTTPS fetch, DNS helpers, TLS probing. One Context per host per run."""
import http.client, re, shutil, socket, ssl, subprocess
from urllib.parse import urlparse
from . import REPO

UA = f"Mozilla/5.0 (compatible; EverydaySecurity/0.2; +{REPO})"
TWO = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.nz", "com.br", "co.jp", "co.za", "com.mx", "com.cn", "co.in", "qc.ca"}

def apex_of(host):
    p = host.split("."); return ".".join(p[-3:]) if ".".join(p[-2:]) in TWO and len(p) >= 3 else ".".join(p[-2:])

def conn(host, port, timeout=10):
    return http.client.HTTPSConnection(host, port, timeout=timeout) if port == 443 else http.client.HTTPConnection(host, port, timeout=timeout)

def fetch(host, port=443, path="/", headers=None, timeout=10, limit=65536):
    """One GET. Returns dict(status, headers, cookies, body) or raises OSError."""
    c = conn(host, port, timeout); h = {"User-Agent": UA, "Accept": "*/*"}; h.update(headers or {})
    try:
        c.request("GET", path, headers=h); r = c.getresponse(); body = r.read(limit)
        return {"status": r.status, "headers": {k.lower(): v for k, v in r.getheaders()}, "cookies": r.msg.get_all("Set-Cookie") or [], "body": body}
    finally: c.close()

def tls_try(host, lo, hi, timeout=10):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try: ctx.minimum_version, ctx.maximum_version = lo, hi
    except (ValueError, ssl.SSLError): return "unavailable"
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t: return t.version()
    except ssl.SSLError as e:
        m = str(e).upper(); return "unavailable" if "UNSUPPORTED_PROTOCOL" in m and "NO_PROTOCOLS" in m else "refused"
    except OSError: return "refused"

class Context:
    def __init__(self, host, deep=False, timeout=10, subdomains=()):
        self.host = host; self.apex = apex_of(host); self.deep = deep; self.timeout = timeout; self.subdomains = list(subdomains)
        self.has_dig = bool(shutil.which("dig")); self._main = None; self._txt = {}

    def main(self):
        """The HTTPS home page after up to 3 HTTPS redirects. {'error':...} if unreachable."""
        if self._main is None:
            try:
                r = fetch(self.host, 443, "/", timeout=self.timeout); fh, hops = self.host, 0
                while r["status"] in (301, 302, 303, 307, 308) and r["headers"].get("location", "").lower().startswith("https://") and hops < 3:
                    u = urlparse(r["headers"]["location"]); fh, hops = u.hostname, hops + 1
                    r = fetch(u.hostname, 443, (u.path or "/") + ("?" + u.query if u.query else ""), timeout=self.timeout)
                r.update(final_host=fh, hops=hops); self._main = r
            except OSError as e: self._main = {"error": str(e)}
        return self._main

    def dig(self, *a):
        if not self.has_dig: return []
        try: return subprocess.run(["dig", "+short", "+time=5", "+tries=1", *a], capture_output=True, text=True, timeout=20).stdout.strip().splitlines()
        except Exception: return []

    def txt(self, name):
        if name not in self._txt: self._txt[name] = [l.replace('" "', "").strip('"') for l in self.dig("TXT", name)]
        return self._txt[name]

    def spf_lookups(self, domain, depth=0, seen=None):
        seen = seen or set()
        if depth > 10 or domain in seen: return 0
        seen.add(domain); recs = [t for t in self.txt(domain) if t.lower().startswith("v=spf1")]
        if not recs: return 0
        n = 0
        for term in recs[0].split()[1:]:
            t = term.lstrip("+-~?").lower()
            if t.startswith(("include:", "redirect=")): n += 1 + self.spf_lookups(re.split("[:=]", t, 1)[1], depth + 1, seen)
            elif t.split(":")[0].split("/")[0] in ("a", "mx", "ptr", "exists"): n += 1
        return n
