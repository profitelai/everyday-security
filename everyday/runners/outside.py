"""More checks that can be judged from outside the server: mail-DNS depth, MX transport security, reverse DNS,
private addresses in public DNS, caching of personal responses and TLS cipher posture."""
import base64, datetime as dt, ipaddress, re, smtplib, socket, ssl, time
from . import group

# ---------- pure helpers (unit-tested) ----------

def _der(b, i=0):
    """Read one DER element at offset i -> (tag, content_start, content_end)."""
    tag = b[i]; n = b[i + 1]; i += 2
    if n & 0x80:
        k = n & 0x7F; n = int.from_bytes(b[i:i + k], "big"); i += k
    return tag, i, i + n

def rsa_bits(spki):
    """Modulus size in bits of an RSA SubjectPublicKeyInfo (DER), or None if it is not RSA or cannot be parsed."""
    try:
        t, s, e = _der(spki); _, s2, e2 = _der(spki, s)            # outer SEQUENCE, algorithm SEQUENCE
        if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" not in spki[s2:e2]: return None
        t3, s3, e3 = _der(spki, e2)                                  # BIT STRING
        t4, s4, e4 = _der(spki, s3 + 1)                              # RSAPublicKey SEQUENCE
        t5, s5, e5 = _der(spki, s4)                                  # modulus INTEGER
        mod = spki[s5:e5].lstrip(b"\x00"); return len(mod) * 8 - (8 - mod[0].bit_length()) if mod else None
    except (IndexError, ValueError): return None

def dkim_key_bits(record):
    """Key size in bits from a DKIM TXT record; 256 for ed25519; 0 for a revoked key (empty p=); None if unreadable."""
    p = re.search(r"\bp=([A-Za-z0-9+/=\s]*)", record)
    if not p: return None
    key = re.sub(r"\s", "", p.group(1))
    if not key: return 0
    if re.search(r"\bk=ed25519", record): return 256
    try: return rsa_bits(base64.b64decode(key + "=" * (-len(key) % 4)))
    except ValueError: return None

def is_private(addr):
    try: ip = ipaddress.ip_address(addr)
    except ValueError: return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved

def dmarc_policy(record):
    m = re.search(r"\bp=(none|quarantine|reject)", record or "", re.I); pct = re.search(r"\bpct=(\d+)", record or "", re.I)
    return (m.group(1).lower() if m else None), (int(pct.group(1)) if pct else 100)

# ---------- runners ----------

SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mxvault", "everlytickey1", "cm", "sig1", "zoho")

def _mx(ctx):
    mx = ctx.dig("MX", ctx.apex)
    return [] if not mx or mx == ["0 ."] else [x.split()[-1].rstrip(".") for x in mx if len(x.split()) == 2]

@group("mail-depth", "MAIL-002", "MAIL-004", "MAIL-005", "MAIL-009")
def mail_depth(ctx):
    ids = ("MAIL-002", "MAIL-004", "MAIL-005", "MAIL-009")
    if not ctx.has_dig: return [(i, "MANUAL", "dig is not installed") for i in ids]
    d = ctx.apex; mx = _mx(ctx); out = []
    # DKIM: look for keys at the common selector names. Selectors are private, so not finding one is not proof of absence.
    found = []
    for s in SELECTORS:
        for t in ctx.txt(f"{s}._domainkey.{d}"):
            if "p=" in t: found.append((s, dkim_key_bits(t)))
    weak = [f"{s}={b}" for s, b in found if b is not None and 0 < b < 2048 and b != 256]
    if weak: out.append(("MAIL-002", "WARN", "DKIM key shorter than 2048 bits: " + ", ".join(weak)))
    elif found: out.append(("MAIL-002", "PASS", "DKIM key(s) at " + ", ".join(f"{s} ({b or '?'} bit)" for s, b in found)))
    else: out.append(("MAIL-002", "WARN" if mx else "INFO", "no DKIM key at the common selector names; your sender's selector may be custom, so confirm in a sent message's headers"))
    # DMARC policy progress
    dm = [t for t in ctx.txt("_dmarc." + d) if t.lower().startswith("v=dmarc1")]
    pol, pct = dmarc_policy(dm[0]) if dm else (None, 100)
    if not dm: out.append(("MAIL-004", "FAIL" if mx else "WARN", "no DMARC record"))
    elif pol == "reject" and pct == 100: out.append(("MAIL-004", "PASS", "DMARC policy is reject"))
    elif pol == "quarantine": out.append(("MAIL-004", "PASS" if pct == 100 else "WARN", f"DMARC policy is quarantine (pct={pct}); reject is the end goal once reports are clean"))
    else: out.append(("MAIL-004", "WARN", f"DMARC policy is {pol or 'missing'}" + (f" with pct={pct}" if pct < 100 else "") + ": moving to quarantine, then reject, is the plan this check expects"))
    # Non-mail domains should say so
    if mx: out.append(("MAIL-005", "INFO", "domain receives mail, so deny-all records do not apply"))
    else:
        spf = [t for t in ctx.txt(d) if t.lower().startswith("v=spf1")]; ok_spf = bool(spf) and spf[0].split()[-1] == "-all" and len(spf[0].split()) == 2
        out.append(("MAIL-005", "PASS" if ok_spf and pol == "reject" else "WARN", f"no MX; SPF {'is deny-all' if ok_spf else 'is not deny-all'}; DMARC {pol or 'missing'}. If this domain never sends mail, publish 'v=spf1 -all' and a reject policy"))
    # Reverse DNS of MX IPs (the inbound hosts; sending IPs are not visible from outside)
    bad = []
    for h in mx[:4]:
        for ip in ctx.dig("A", h)[:2]:
            ptr = ctx.dig("-x", ip)
            if not ptr: bad.append(f"{ip} has no PTR"); continue
            back = ctx.dig("A", ptr[0].rstrip("."))
            if ip not in back: bad.append(f"{ip} -> {ptr[0].rstrip('.')} does not resolve back")
    out.append(("MAIL-009", "MANUAL" if not mx else ("WARN" if bad else "PASS"), "no MX hosts" if not mx else ("; ".join(bad) if bad else f"reverse DNS matches for the {len(mx[:4])} MX host(s). Your outgoing IPs need the same check (see the test steps)")))
    return out

def name_matches(host, names):
    """True if `host` equals a certificate DNS name or matches a single-label wildcard such as *.example.com."""
    h = host.rstrip(".").lower()
    for n in names:
        n = n.rstrip(".").lower()
        if n == h or (n.startswith("*.") and "." in h and h.split(".", 1)[1] == n[2:]): return True
    return False

def cert_names(cert):
    """DNS names a certificate is valid for: the subjectAltName DNS entries, or the common name only when there are none."""
    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if san: return san
    return [v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"]

def _dn(cert, field):
    return ", ".join(v for rdn in cert.get(field, ()) for k, v in rdn if k in ("commonName", "organizationName"))

def probe_mx(host, timeout=8):
    """One SMTP connection to an MX host on port 25. Records what happened; judges nothing."""
    ob = {"host": host, "port": 25, "reachable": False}
    try: s = smtplib.SMTP(host, 25, timeout=timeout)
    except (OSError, smtplib.SMTPException) as e: ob["error"] = type(e).__name__; return ob
    ob["reachable"] = True
    try:
        s.ehlo(); ob["starttls"] = s.has_extn("starttls")
        if not ob["starttls"]: return ob
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_REQUIRED; c.load_default_certs()   # chain checked here, name checked below so the two stay separate
        try: s.starttls(context=c)
        except ssl.SSLCertVerificationError as e: ob["chain"] = "untrusted"; ob["chain_error"] = e.verify_message; ob["verify_code"] = e.verify_code; return ob
        except ssl.SSLError as e: ob["chain"] = "error"; ob["error"] = type(e).__name__; return ob
        ob["chain"] = "trusted"; ob["tls_version"] = s.sock.version(); cert = s.sock.getpeercert()
        ob["names"] = cert_names(cert); ob["name_matches"] = name_matches(host, ob["names"]); ob["issuer"] = _dn(cert, "issuer"); ob["not_after"] = cert.get("notAfter")
        if cert.get("notAfter"): ob["days_left"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    except (OSError, smtplib.SMTPException) as e: ob["error"] = type(e).__name__
    finally:
        try: s.close()
        except Exception: pass
    return ob

def _mta_sts_mode(ctx):
    """'enforce', 'testing', 'none' or None, from the MTA-STS policy file (RFC 8461); None when there is no policy."""
    import http.client
    try:
        c = http.client.HTTPSConnection("mta-sts." + ctx.apex, timeout=8); c.request("GET", "/.well-known/mta-sts.txt", headers={"User-Agent": "EverydaySecurity"}); r = c.getresponse(); body = r.read(4096).decode("utf-8", "ignore")
        m = re.search(r"(?mi)^mode:\s*(\w+)", body) if r.status == 200 else None
        return m.group(1).lower() if m else None
    except (OSError, ValueError): return None

def judge_mx_tls(obs, policy):
    """Decide MAIL-007 from recorded observations. Returns (status, detail, extra) where extra holds the evidence and a confidence.
    Three separate questions per mail host: is the certificate chain trusted, does the name match the host contacted, is it near expiry.
    A name mismatch is a WARN, and a FAIL only when MTA-STS 'enforce' or DANE is published, because then senders will refuse the mail."""
    ev = {"hosts": obs, "policy": policy, "checked": dt.datetime.utcnow().isoformat() + "Z"}
    if not obs: return "MANUAL", "no MX hosts found", {"evidence": ev}
    reach = [o for o in obs if o.get("reachable")]
    if not reach: return "INCONCLUSIVE", "port 25 could not be reached from this network (many providers block outbound 25); run the check from a server", {"evidence": ev, "confidence": "low"}
    strict = policy.get("mta_sts") == "enforce" or bool(policy.get("dane"))
    fails, warns, unsure, good = [], [], [], []
    for o in reach:
        h = o["host"]
        if o.get("error") and not o.get("starttls"): unsure.append(f"{h}: connected but the TLS test failed ({o['error']})"); continue
        if not o.get("starttls"): fails.append(f"{h}: does not offer STARTTLS, so mail is sent in clear text"); continue
        if o.get("chain") == "untrusted":
            if o.get("verify_code") == 10: fails.append(f"{h}: certificate has expired")
            else: warns.append(f"{h}: certificate chain is not trusted ({o.get('chain_error')})")
            continue
        if o.get("chain") == "error": unsure.append(f"{h}: TLS handshake failed ({o.get('error')})"); continue
        parts = ["certificate chain trusted"]
        if o.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"): fails.append(f"{h}: negotiated {o['tls_version']}"); continue
        if not o.get("name_matches"):
            msg = f"{h}: certificate name does not match this host (certificate is for {', '.join(o.get('names') or ['?'])})"
            (fails if strict else warns).append(msg + ("; MTA-STS enforce or DANE is published, so senders that honour it will refuse delivery" if strict else "; usual with hosted mail, and only matters if MTA-STS enforce or DANE is used"))
        else: parts.append("name matches")
        d = o.get("days_left")
        if d is not None and d < 14: warns.append(f"{h}: certificate expires in {d} days")
        elif d is not None: parts.append(f"valid for {d} more days")
        good.append(f"{h}: " + ", ".join(parts) + f", {o.get('tls_version', '?')}")
    notes = "; ".join(fails + warns + unsure)
    if fails: return "FAIL", notes, {"evidence": ev, "confidence": "high"}
    if warns: return "WARN", notes + ("" if not good else " | other checks: " + "; ".join(good)), {"evidence": ev, "confidence": "medium"}
    if unsure: return "INCONCLUSIVE", notes, {"evidence": ev, "confidence": "low"}
    return "PASS", f"{len(reach)} MX host(s): " + "; ".join(good), {"evidence": ev, "confidence": "high"}

@group("mx-tls", "MAIL-007")
def mx_tls(ctx):
    hosts = _mx(ctx) if ctx.has_dig else []
    if not hosts: return [("MAIL-007", "MANUAL", "no MX hosts found or dig missing")]
    obs = [probe_mx(h) for h in hosts[:4]]
    policy = {"mta_sts": _mta_sts_mode(ctx), "dane": any(ctx.dig("TLSA", f"_25._tcp.{h}") for h in hosts[:4])}
    st, detail, extra = judge_mx_tls(obs, policy)
    return [("MAIL-007", st, detail, extra)]

COMMON_INTERNAL = ("intranet", "internal", "vpn", "dev", "staging", "test", "admin", "db", "mysql", "git", "jenkins", "ldap", "mail", "ftp", "office", "nas", "router")

@group("dns-private", "DNS-009")
def dns_private(ctx):
    if not ctx.has_dig: return [("DNS-009", "MANUAL", "dig is not installed")]
    names = [ctx.apex, ctx.host] + [f"{n}.{ctx.apex}" for n in COMMON_INTERNAL] + ctx.subdomains; seen, hits = set(), []
    for n in names:
        if n in seen: continue
        seen.add(n)
        for ip in ctx.dig("A", n) + ctx.dig("AAAA", n):
            if is_private(ip): hits.append(f"{n} -> {ip}")
    return [("DNS-009", "WARN" if hits else "PASS", ("private addresses in public DNS: " + "; ".join(hits[:6])) if hits else f"{len(seen)} names checked, none resolve to a private address")]

@group("cache", "HDR-008")
def cache(ctx):
    m = ctx.main()
    if "error" in m: return [("HDR-008", "MANUAL", "site not reachable")]
    h = m["headers"]; cc = h.get("cache-control", "").lower(); cookies = m["cookies"]; pragma = h.get("pragma", "").lower()
    private = "no-store" in cc or "private" in cc or "no-cache" in cc
    pub_long = re.search(r"max-age=(\d+)", cc); long_ = bool(pub_long and int(pub_long.group(1)) > 300 and "public" in cc)
    if cookies and long_ : return [("HDR-008", "FAIL", f"page sets a cookie and is publicly cacheable: Cache-Control: {cc}")]
    if cookies and not private and not cc: return [("HDR-008", "WARN", "page sets a cookie but sends no Cache-Control, so caches may keep it")]
    return [("HDR-008", "PASS", f"Cache-Control: {cc or 'not set'}; {'sets a cookie' if cookies else 'no cookie on the home page'}. Logged-in pages need a manual look")]

@group("ciphers", "TLS-003")
def ciphers(ctx):
    host = ctx.host; res = []
    def attempt(cipher_string, label, tls12=True):
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE   # on purpose: we only measure which cipher the server accepts; no data is sent
        try:
            c.set_ciphers(cipher_string); c.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ssl.SSLError, ValueError): return None
        try:
            with socket.create_connection((host, 443), timeout=ctx.timeout) as s, c.wrap_socket(s, server_hostname=host) as t: return t.cipher()[0]
        except (ssl.SSLError, OSError): return False
    try:
        with socket.create_connection((host, 443), timeout=ctx.timeout) as s, ssl.create_default_context().wrap_socket(s, server_hostname=host) as t: best = t.cipher()[0]
    except (ssl.SSLError, OSError): best = None
    if best is None: return [("TLS-003", "MANUAL", "could not complete a modern handshake")]
    for cs, label in (("kRSA", "static-RSA key exchange (no forward secrecy)"), ("3DES:RC4:DES:EXPORT:NULL:aNULL", "weak or broken ciphers")):
        r = attempt(cs, label)
        if r: res.append(f"accepts {label}: {r}")
    return [("TLS-003", "FAIL" if any("weak" in x for x in res) else "WARN" if res else "PASS", "; ".join(res) if res else f"best cipher {best}; legacy static-RSA and broken ciphers refused (as far as this client can test)")]
