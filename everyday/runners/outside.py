"""More checks that can be judged from outside the server: mail-DNS depth, MX transport security, reverse DNS,
private addresses in public DNS, caching of personal responses and TLS cipher posture."""
import base64, ipaddress, re, smtplib, socket, ssl
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

@group("mx-tls", "MAIL-007")
def mx_tls(ctx):
    hosts = _mx(ctx) if ctx.has_dig else []
    if not hosts: return [("MAIL-007", "MANUAL" if ctx.has_dig else "MANUAL", "no MX hosts found or dig missing")]
    res, soft, reachable = [], [], 0
    for h in hosts[:4]:
        try:
            s = smtplib.SMTP(h, 25, timeout=8)
        except (OSError, smtplib.SMTPException): continue
        reachable += 1
        try:
            s.ehlo()
            if not s.has_extn("starttls"): res.append(f"{h}: no STARTTLS"); continue
            c = ssl.create_default_context()
            try: s.starttls(context=c)
            except ssl.SSLError as e: soft.append(f"{h}: certificate does not validate for this name (common with hosted mail, but worth confirming)"); continue
            v = s.sock.version() if hasattr(s.sock, "version") else "?"
            if v in ("TLSv1", "TLSv1.1", "SSLv3"): res.append(f"{h}: negotiated {v}")
        except (OSError, smtplib.SMTPException) as e: res.append(f"{h}: {type(e).__name__}")
        finally:
            try: s.close()
            except Exception: pass
    if not reachable: return [("MAIL-007", "MANUAL", "port 25 not reachable from this network (many providers block outbound 25); run the test from a server")]
    return [("MAIL-007", "FAIL" if res else "WARN" if soft else "PASS", "; ".join(res + soft) if res or soft else f"{reachable} MX host(s) offer STARTTLS with a valid certificate on TLS 1.2 or newer")]

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
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
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
