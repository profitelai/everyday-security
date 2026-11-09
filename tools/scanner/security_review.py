#!/usr/bin/env python3
"""
Recurring external + host security review for every domain served by this server.

  sudo python3 /opt/security-review/security_review.py            # full run (weekly cron + on demand)
  sudo python3 /opt/security-review/security_review.py --no-mail  # run without the status e-mail

What it does (read-only, defensive, our own domains only):
  * discovers every server_name in nginx (minus wildcards), groups them by apex domain
  * per hostname: DNS (A/AAAA/CNAME, Cloudflare-proxied, dangling CNAME), TLS (expiry, hostname match,
    old protocol versions), HTTP->HTTPS redirect, OWASP baseline response headers, information-disclosure
    headers, cookie flags, exposed sensitive paths (.env, .git, phpinfo, backups, ...), directory listing,
    /.well-known/security.txt
  * per apex domain: MX, SPF, DMARC policy, DKIM selector "mail"
  * host: public listeners x ufw allow rules (what the internet can really reach), docker-published ports vs
    DOCKER-USER rules, pending security updates / container CVE counts / reboot-required from the daily
    trivy scan (/root/security-report.txt), fail2ban, SSH exposure
  * writes /var/lib/security-review/runs/<stamp>/{findings.json,report.html,summary.md}, keeps history in git,
    diffs against the previous run, opens/closes tickets (tickets/open|closed/*.md) for critical/high findings,
    and e-mails a SHORT status to the owner ONLY when something new and significant appeared
    (new critical/high, certificate < 14 days, newly exposed port/path).

Checks cover common public practice: TLS and certificate expiry, HTTP security headers, DMARC/SPF/DKIM, exposed paths and ports, file-upload exposure.
Standard library only.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, html, json, os, re, socket, ssl, subprocess, sys, urllib.request, urllib.error
from collections import defaultdict
from http.client import HTTPResponse

BASE = '/var/lib/security-review'
RUNS = os.path.join(BASE, 'runs'); TICKETS = os.path.join(BASE, 'tickets')
OWNER_EMAIL = os.environ.get('SECURITY_REVIEW_EMAIL', '')
FROM_EMAIL = os.environ.get('SECURITY_REVIEW_FROM', 'security-review@localhost')
SERVER_IP = os.environ.get('SECURITY_REVIEW_SERVER_IP', '')
NGINX_DIR = '/etc/nginx/sites-enabled'
TRIVY_REPORT = '/root/security-report.txt'
UA = 'Mozilla/5.0 (compatible; EverydaySecurity/0.1; +https://github.com/profitelai/everyday-security)'
TIMEOUT = 12
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
CF_PREFIXES = ('104.16.', '104.17.', '104.18.', '104.19.', '104.2', '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.7', '188.114.', '162.158.', '141.101.', '108.162.', '173.245.', '103.21.', '103.22.', '103.31.', '190.93.', '197.234.', '198.41.')
SENSITIVE_PATHS = [
    ('/.env', 'critical', r'^[A-Z_][A-Z0-9_]*=', 'environment file with secrets is downloadable'),
    ('/.git/HEAD', 'critical', r'^ref: refs/', 'git repository exposed (source + history + possibly secrets)'),
    ('/.git/config', 'critical', r'\[core\]', 'git repository exposed'),
    ('/wp-config.php.bak', 'critical', r'DB_PASSWORD', 'WordPress config backup exposed'),
    ('/config.php.bak', 'high', r'<\?php', 'PHP config backup exposed'),
    ('/phpinfo.php', 'high', r'phpinfo\(\)|PHP Version', 'phpinfo page exposed'),
    ('/info.php', 'high', r'phpinfo\(\)|PHP Version', 'phpinfo page exposed'),
    ('/server-status', 'medium', r'Apache Server Status|Active connections', 'server status page exposed'),
    ('/.DS_Store', 'low', r'^\x00\x00\x00\x01Bud1', 'macOS folder listing file exposed'),
    ('/composer.json', 'low', r'"require"', 'composer manifest exposed (reveals dependency versions)'),
    ('/package.json', 'low', r'"dependencies"|"scripts"', 'package manifest exposed (reveals dependency versions)'),
    ('/.svn/entries', 'high', r'^\d+\s*$', 'Subversion metadata exposed'),
    ('/storage/logs/laravel.log', 'high', r'\[\d{4}-\d{2}-\d{2}', 'application log exposed'),
    ('/adminer.php', 'high', r'Adminer', 'database admin tool exposed'),
    ('/backup.zip', 'high', r'^PK', 'backup archive downloadable'),
    ('/db.sql', 'critical', r'CREATE TABLE|INSERT INTO', 'database dump downloadable'),
    ('/.htpasswd', 'high', r'^[^:\s]+:\$', 'password file exposed'),
]
LISTING_PATHS = ['/uploads/', '/images/', '/assets/', '/backup/', '/files/', '/static/']


def sh(cmd: list[str], timeout=60) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:  # noqa: BLE001
        return f'__error__ {e}'


def dig(name: str, rtype: str) -> list[str]:
    # Public resolver on purpose: the server's own /etc/hosts maps its hostname to 127.0.1.1, which is not what visitors see.
    out = sh(['dig', '@1.1.1.1', '+short', '+time=4', '+tries=2', rtype, name])
    return [l.strip() for l in out.splitlines() if l.strip() and not l.startswith('__error__')]


def apex(host: str) -> str:
    parts = host.split('.')
    if len(parts) >= 3 and parts[-2] in ('co', 'com', 'qc', 'on') and parts[-1] == 'ca' and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


class Finding:
    def __init__(self, target, severity, check, title, detail='', fix=''):
        self.target, self.severity, self.check, self.title, self.detail, self.fix = target, severity, check, title, detail, fix

    @property
    def key(self):  # stable identity across runs
        return hashlib.sha1(f'{self.target}|{self.check}|{self.title}'.encode()).hexdigest()[:12]

    def d(self):
        return {'key': self.key, 'target': self.target, 'severity': self.severity, 'check': self.check, 'title': self.title, 'detail': self.detail, 'fix': self.fix}


F: list[Finding] = []
def add(*a, **k): F.append(Finding(*a, **k))


# ----------------------------------------------------------------------------- discovery
def discover_hosts() -> list[str]:
    hosts = set()
    for fn in os.listdir(NGINX_DIR):
        try:
            txt = open(os.path.join(NGINX_DIR, fn), encoding='utf8', errors='ignore').read()
        except OSError:
            continue
        for m in re.finditer(r'^\s*server_name\s+([^;]+);', txt, re.M):
            for h in m.group(1).split():
                h = h.strip().lower()
                if h and h != '_' and '*' not in h and '.' in h:
                    hosts.add(h)
    return sorted(hosts)


# ----------------------------------------------------------------------------- HTTP helpers
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url: str, follow=False, method='GET') -> tuple[int | None, dict, bytes, str]:
    handlers = [] if follow else [NoRedirect()]
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(*handlers, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'}, method=method)
    try:
        r: HTTPResponse = opener.open(req, timeout=TIMEOUT)
        body = r.read(200_000)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, body, r.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200_000)
        except Exception:  # noqa: BLE001
            body = b''
        return e.code, {k.lower(): v for k, v in e.headers.items()}, body, url
    except Exception as e:  # noqa: BLE001
        return None, {'__error__': str(e)[:120]}, b'', url


# ----------------------------------------------------------------------------- per-host checks
def check_dns(host: str) -> dict:
    a = dig(host, 'A'); aaaa = dig(host, 'AAAA'); cname = dig(host, 'CNAME')
    info = {'a': a, 'aaaa': aaaa, 'cname': cname}
    ips = [x for x in a if re.match(r'^\d+\.\d+\.\d+\.\d+$', x)]
    info['cloudflare'] = any(ip.startswith(CF_PREFIXES) for ip in ips)
    info['direct'] = SERVER_IP in ips
    if cname and not ips:
        add(host, 'high', 'dns-dangling', 'CNAME points to a name that does not resolve',
            f'CNAME {cname[0]} has no A record. Subdomain takeover risk if the target is a third-party service.',
            'Remove the CNAME or point it at a live target.')
    if not a and not cname:
        add(host, 'info', 'dns-none', 'No DNS record (served by nginx but not resolvable)', 'Dead vhost; harmless but clutter.', 'Remove the nginx server block or add DNS.')
    elif ips and not info['cloudflare'] and not info['direct']:
        add(host, 'medium', 'dns-elsewhere', 'DNS points to another server', f'A = {", ".join(ips)} (not this server, not Cloudflare).', 'Confirm the record is intentional.')
    return info


def check_tls(host: str, resolvable: bool) -> dict:
    out = {}
    if not resolvable:
        return out
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert(); out['protocol'] = ss.version()
        exp = dt.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc)
        days = (exp - dt.datetime.now(dt.timezone.utc)).days
        out['cert_days_left'] = days; out['issuer'] = dict(x[0] for x in cert.get('issuer', ()))
        if days < 7: add(host, 'critical', 'tls-expiry', f'Certificate expires in {days} days', f'Expires {exp.date()}.', 'Renew now (certbot renew / Cloudflare edge cert).')
        elif days < 21: add(host, 'high', 'tls-expiry', f'Certificate expires in {days} days', f'Expires {exp.date()}.', 'Check auto-renewal.')
    except ssl.SSLCertVerificationError as e:
        add(host, 'high', 'tls-invalid', 'TLS certificate does not validate', str(e)[:160], 'Fix the certificate (hostname mismatch / expired / wrong chain).')
        return out
    except Exception as e:  # noqa: BLE001
        out['error'] = str(e)[:120]
        add(host, 'medium', 'tls-unreachable', 'HTTPS not reachable on 443', str(e)[:120], 'Serve HTTPS or remove the hostname.')
        return out
    # legacy protocol acceptance (direct origins only; Cloudflare edge is managed by Cloudflare)
    for proto_name, flag in (('TLSv1', getattr(ssl, 'OP_NO_TLSv1_1', 0) | getattr(ssl, 'OP_NO_TLSv1_2', 0) | getattr(ssl, 'OP_NO_TLSv1_3', 0)),):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                c.minimum_version = ssl.TLSVersion.TLSv1; c.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((host, 443), timeout=8) as s2, c.wrap_socket(s2, server_hostname=host) as s3:
                add(host, 'medium', 'tls-legacy', f'Server still accepts {s3.version()}', 'TLS 1.0/1.1 are deprecated (RFC 8996).', 'Set ssl_protocols TLSv1.2 TLSv1.3 in nginx.')
        except Exception:  # noqa: BLE001
            pass
    return out


def check_http(host: str, resolvable: bool) -> dict:
    out = {}
    if not resolvable:
        return out
    st, hd, body, _ = fetch(f'http://{host}/')
    out['http_status'] = st
    if st is None:
        pass
    elif st in (301, 302, 307, 308) and str(hd.get('location', '')).startswith('https://'):
        out['http_redirect'] = True
        if st in (302, 307): add(host, 'low', 'http-redirect-temp', f'HTTP redirects to HTTPS with a temporary {st}', 'Search engines and browsers cache a 301/308 better.', 'Use 301 or 308.')
    else:
        add(host, 'medium', 'http-no-redirect', 'HTTP does not redirect to HTTPS', f'http:// answered {st} without a Location to https://.', 'Add a server block on :80 that returns 301 https://$host$request_uri.')
    st, hd, body, final = fetch(f'https://{host}/', follow=True)
    out['https_status'] = st; out['final_url'] = final
    if st is None:
        add(host, 'medium', 'https-error', 'HTTPS homepage not reachable', hd.get('__error__', ''), 'Fix the origin or remove the hostname.')
        return out
    if st >= 500:
        add(host, 'medium', 'https-5xx', f'Homepage returns {st}', 'Site is erroring for visitors.', 'Check the application / upstream.')
    hs = hd.get('strict-transport-security', '')
    if not hs:
        add(host, 'medium', 'hdr-hsts', 'Missing Strict-Transport-Security', 'Without HSTS a first visit over HTTP can be intercepted.', 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;')
    else:
        m = re.search(r'max-age=(\d+)', hs)
        if m and int(m.group(1)) < 15552000: add(host, 'low', 'hdr-hsts-short', f'HSTS max-age is short ({m.group(1)}s)', 'Recommended at least 6 months.', 'Raise max-age to 31536000.')
    if 'x-content-type-options' not in hd: add(host, 'low', 'hdr-xcto', 'Missing X-Content-Type-Options: nosniff', 'Browsers may sniff content types (upload/XSS risk).', 'add_header X-Content-Type-Options nosniff always;')
    csp = hd.get('content-security-policy', '')
    if 'x-frame-options' not in hd and 'frame-ancestors' not in csp:
        add(host, 'low', 'hdr-frame', 'No clickjacking protection (X-Frame-Options / frame-ancestors)', 'The site can be framed by other sites.', "add_header X-Frame-Options SAMEORIGIN always; or CSP frame-ancestors 'self'.")
    if not csp: add(host, 'low', 'hdr-csp', 'No Content-Security-Policy', 'CSP limits the damage of injected scripts.', 'Start with a report-only policy, then enforce.')
    if 'referrer-policy' not in hd: add(host, 'info', 'hdr-referrer', 'No Referrer-Policy', 'Full URLs leak to third parties in the Referer header.', 'add_header Referrer-Policy strict-origin-when-cross-origin always;')
    if 'permissions-policy' not in hd: add(host, 'info', 'hdr-permissions', 'No Permissions-Policy', 'Camera/microphone/geolocation not restricted.', 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;')
    for h in ('server', 'x-powered-by', 'x-generator', 'x-aspnet-version'):
        v = hd.get(h, '')
        if v and re.search(r'\d', v) and v.lower() != 'cloudflare':
            add(host, 'low', f'hdr-disclose-{h}', f'{h} header reveals a version', f'{h}: {v}', 'Hide versions (server_tokens off; remove X-Powered-By).')
    cookies = [c for k, c in hd.items() if k == 'set-cookie'] if isinstance(hd.get('set-cookie'), str) else []
    if hd.get('set-cookie'):
        for c in str(hd['set-cookie']).split('\n'):
            cl = c.lower()
            if 'secure' not in cl or 'httponly' not in cl:
                if not cl.startswith(('__cf', 'cf_')):
                    add(host, 'medium', 'cookie-flags', 'Cookie set without Secure and HttpOnly', c.split(';')[0][:80], 'Set Secure; HttpOnly; SameSite=Lax on session cookies.')
                    break
    home_hash = hashlib.sha1(body[:50000]).hexdigest()
    # sensitive paths: must return 200 with matching content and differ from the homepage (SPA catch-alls)
    for path, sev, rx, title in SENSITIVE_PATHS:
        s2, h2, b2, _ = fetch(f'https://{host}{path}')
        if s2 == 200 and hashlib.sha1(b2[:50000]).hexdigest() != home_hash and re.search(rx, b2[:4000].decode('latin1'), re.M):
            add(host, sev, f'path{path}', f'Exposed: {path}', title, 'Block the path in nginx (location ~ /\\. { deny all; }) and remove the file.')
    for path in LISTING_PATHS:
        s2, h2, b2, _ = fetch(f'https://{host}{path}')
        if s2 == 200 and re.search(rb'<title>Index of /|Parent Directory', b2[:4000], re.I):
            add(host, 'medium', f'listing{path}', f'Directory listing enabled at {path}', 'Lists every uploaded file.', 'autoindex off; in nginx.')
    s2, h2, b2, _ = fetch(f'https://{host}/.well-known/security.txt')
    out['security_txt'] = s2 == 200 and b'Contact:' in b2[:2000]
    return out


def check_mail_domain(domain: str) -> dict:
    out = {'mx': dig(domain, 'MX')}
    txt = [t.strip('"').replace('" "', '') for t in dig(domain, 'TXT')]
    spf = [t for t in txt if t.lower().startswith('v=spf1')]
    dmarc = [t.strip('"').replace('" "', '') for t in dig(f'_dmarc.{domain}', 'TXT')]
    dmarc = [t for t in dmarc if t.lower().startswith('v=dmarc1')]
    dkim = dig(f'mail._domainkey.{domain}', 'TXT')
    out.update({'spf': spf, 'dmarc': dmarc, 'dkim_mail_selector': bool(dkim)})
    sends_mail = bool(out['mx']) or bool(spf)
    if not spf:
        add(domain, 'high' if sends_mail else 'medium', 'mail-spf', 'No SPF record', 'Anyone can send mail as this domain and it passes nothing.', 'Publish v=spf1 ... -all (or ~all) in DNS.')
    elif spf and spf[0].rstrip().endswith('+all'):
        add(domain, 'high', 'mail-spf-all', 'SPF ends with +all', 'Authorises every sender on earth.', 'End with -all or ~all.')
    if not dmarc:
        add(domain, 'high' if sends_mail else 'medium', 'mail-dmarc', 'No DMARC record', 'Spoofed mail is not rejected or reported (Gmail/Yahoo bulk-sender rules require DMARC).', 'Publish _dmarc TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>".')
    else:
        m = re.search(r'\bp=(\w+)', dmarc[0])
        pol = m.group(1).lower() if m else 'none'
        if pol == 'none': add(domain, 'medium', 'mail-dmarc-none', 'DMARC policy is p=none (monitor only)', dmarc[0][:120], 'Move to p=quarantine, then p=reject once reports are clean.')
        if 'rua=' not in dmarc[0]: add(domain, 'low', 'mail-dmarc-rua', 'DMARC has no reporting address (rua)', 'You never learn who spoofs the domain.', 'Add rua=mailto:dmarc@<domain>.')
    if sends_mail and not dkim:
        add(domain, 'medium', 'mail-dkim', 'No DKIM key at selector "mail"', 'Outbound mail from this domain may not be signed.', 'Add the domain to opendkim SigningTable/KeyTable and publish mail._domainkey.')
    return out


# ----------------------------------------------------------------------------- host checks
def check_host() -> dict:
    out = {}
    ufw = sh(['ufw', 'status'])
    out['ufw_active'] = 'Status: active' in ufw
    if not out['ufw_active']:
        add('host', 'critical', 'ufw-off', 'Firewall (ufw) is not active', 'Every listening service is reachable.', 'ufw enable with deny incoming by default.')
    allow_any = set(); allow_from = defaultdict(set)
    for line in ufw.splitlines():
        m = re.match(r'^(\S+?)(?:/tcp|/udp)?(?: \(v6\))?\s+ALLOW\s+(?:IN\s+)?(\S+)', line.strip())
        if m:
            port, src = m.group(1), m.group(2)
            (allow_any.add(port) if src.lower() == 'anywhere' else allow_from[port].add(src))
    ss_out = sh(['ss', '-tlnpH'])
    public = {}
    for line in ss_out.splitlines():
        m = re.search(r'\s(\*|0\.0\.0\.0|\[::\]):(\d+)\s.*?users:\(\("([^"]+)"', line)
        if m:
            public[m.group(2)] = m.group(3)
    out['public_listeners'] = public
    dock = sh(['iptables', '-S', 'DOCKER-USER'])
    docker_drop = set(re.findall(r'--ctorigdstport (\d+) -j DROP', dock))
    exposed = {}
    for port, proc in sorted(public.items(), key=lambda x: int(x[0])):
        if port in allow_any:
            exposed[port] = proc
        elif proc == 'docker-proxy' and port not in docker_drop and port not in allow_from:
            exposed[port] = proc + ' (docker bypasses ufw)'
    out['internet_exposed'] = exposed
    expected = {'25', '80', '443', '465', '587', '110', '143', '993', '995'}
    for port, proc in exposed.items():
        if port in expected:
            continue
        sev = 'critical' if proc.startswith(('postgres', 'mysqld', 'mongod', 'redis')) else 'high' if port != '1111' else 'low'
        title = f'Port {port} ({proc}) reachable from the whole internet'
        fix = 'Bind to 127.0.0.1 or restrict with ufw to your IP.' if port != '1111' else 'SSH on 1111 open to Anywhere: consider restricting to known IPs or keys-only + fail2ban (check both).'
        add('host', sev, f'port-{port}', title, 'ufw allows Anywhere' if port in allow_any else 'docker published port, no DOCKER-USER drop', fix)
    allow_restricted = {p: sorted(s) for p, s in allow_from.items() if p in public and p not in allow_any}
    out['allowlisted_ports'] = allow_restricted
    f2b = sh(['fail2ban-client', 'status'])
    out['fail2ban'] = 'Jail list' in f2b
    if not out['fail2ban']:
        add('host', 'medium', 'fail2ban', 'fail2ban is not running', 'Brute force on SSH/mail/IMAP is not throttled.', 'systemctl enable --now fail2ban.')
    # daily trivy/apt report
    try:
        rep = open(TRIVY_REPORT, encoding='utf8', errors='ignore').read()
        out['daily_scan_header'] = rep.splitlines()[0] if rep else ''
        m = re.search(r'pending security updates:\s*(\d+)', rep)
        pend = int(m.group(1)) if m else None
        out['pending_security_updates'] = pend
        if pend and pend > 0: add('host', 'high' if pend > 5 else 'medium', 'apt-pending', f'{pend} pending security updates', 'unattended-upgrades runs once a day; check it is working.', 'apt-get install --only-upgrade of the security packages.')
        if re.search(r'reboot.required:\s*(yes|true)', rep, re.I): add('host', 'medium', 'reboot', 'Reboot required (kernel/libc updated)', 'The running kernel is not the patched one.', 'Schedule a reboot window.')
        imgs = re.findall(r'^\s*(\S+)\s*:\s*(\d+) HIGH/CRITICAL', rep, re.M)
        out['container_cves'] = {k: int(v) for k, v in imgs}
        worst = [(k, v) for k, v in out['container_cves'].items() if v >= 500]
        for k, v in worst: add('host', 'medium', f'cve-{k}', f'Container image {k}: {v} HIGH/CRITICAL CVEs', 'Image is far behind upstream patches.', 'Pull/rebuild the image on its latest tag (see project notes for the correct compose invocation).')
        # stale daily scan?
        m = re.search(r'SECURITY SCAN (\d{4}-\d{2}-\d{2})', rep)
        if m and (dt.date.today() - dt.date.fromisoformat(m.group(1))).days > 2:
            add('host', 'medium', 'scan-stale', 'Daily trivy/apt scan has not run for over 2 days', f'Last: {m.group(1)}', 'Check cron 30 3 * * * /root/security-scan.sh.')
    except OSError:
        add('host', 'medium', 'scan-missing', 'Daily security scan report not found', TRIVY_REPORT, 'Reinstall /root/security-scan.sh cron.')
    sshd = sh(['sshd', '-T'])
    if re.search(r'^passwordauthentication yes', sshd, re.M): add('host', 'high', 'ssh-password', 'SSH allows password authentication', 'Brute-forceable.', 'PasswordAuthentication no in sshd_config (keys only).')
    if re.search(r'^permitrootlogin yes', sshd, re.M): add('host', 'medium', 'ssh-root', 'SSH allows direct root login with password', 'Prefer prohibit-password.', 'PermitRootLogin prohibit-password.')
    return out


# ----------------------------------------------------------------------------- history, tickets, mail
def load_previous(runs_dir: str, current: str) -> dict | None:
    prev = sorted(d for d in os.listdir(runs_dir) if d != current and os.path.isfile(os.path.join(runs_dir, d, 'findings.json')))
    if not prev:
        return None
    return json.load(open(os.path.join(runs_dir, prev[-1], 'findings.json'), encoding='utf8'))


def significant(f: dict) -> bool:
    return f['severity'] in ('critical', 'high') or f['check'].startswith(('tls-expiry', 'port-', 'path/'))


def update_tickets(findings: list[dict], stamp: str) -> tuple[list[str], list[str]]:
    os.makedirs(os.path.join(TICKETS, 'open'), exist_ok=True); os.makedirs(os.path.join(TICKETS, 'closed'), exist_ok=True)
    opened, closed = [], []
    live = {f['key']: f for f in findings if f['severity'] in ('critical', 'high')}
    for key, f in live.items():
        p = os.path.join(TICKETS, 'open', f'{key}.md')
        if not os.path.exists(p):
            open(p, 'w', encoding='utf8').write(f"""---
ticket: {key}
opened: {stamp}
severity: {f['severity']}
target: {f['target']}
check: {f['check']}
status: open
---
# {f['title']}

**Where:** {f['target']}
**Detail:** {f['detail']}
**Fix:** {f['fix']}

Everyday Security 0.1.0: checks implemented from public standards (see docs/PROVENANCE.md).
Log of actions (append below):
""")
            opened.append(key)
    for fn in os.listdir(os.path.join(TICKETS, 'open')):
        key = fn[:-3]
        if key not in live:
            src = os.path.join(TICKETS, 'open', fn); dst = os.path.join(TICKETS, 'closed', fn)
            txt = open(src, encoding='utf8').read().replace('status: open', f'status: closed\nclosed: {stamp}', 1)
            open(dst, 'w', encoding='utf8').write(txt + f"\n- {stamp}: finding no longer present; ticket closed automatically.\n"); os.remove(src)
            closed.append(key)
    return opened, closed


def render_html(stamp: str, hosts_info: dict, mail_info: dict, host_info: dict, findings: list[dict], new_keys: set, resolved: list[dict], open_tickets: int) -> str:
    counts = defaultdict(int)
    for f in findings: counts[f['severity']] += 1
    sev_color = {'critical': '#b91c1c', 'high': '#c2410c', 'medium': '#a16207', 'low': '#1d4ed8', 'info': '#4b5563'}
    e = html.escape
    rows = ''.join(
        f"<tr class='{f['severity']}'><td><span class='pill' style='background:{sev_color[f['severity']]}'>{f['severity']}</span>{' <span class=new>NEW</span>' if f['key'] in new_keys else ''}</td>"
        f"<td>{e(f['target'])}</td><td><b>{e(f['title'])}</b><div class=muted>{e(f['detail'])}</div></td><td class=fix>{e(f['fix'])}</td></tr>"
        for f in sorted(findings, key=lambda x: (SEVERITY_ORDER[x['severity']], x['target'])))
    by_host = defaultdict(list)
    for f in findings: by_host[f['target']].append(f['severity'])
    def badge(h):
        s = by_host.get(h, [])
        worst = min(s, key=lambda x: SEVERITY_ORDER[x]) if s else 'ok'
        return f"<span class='pill' style='background:{sev_color.get(worst, '#15803d')}'>{worst}</span>"
    host_rows = ''.join(
        f"<tr><td>{e(h)}</td><td>{'Cloudflare' if i.get('dns', {}).get('cloudflare') else 'direct' if i.get('dns', {}).get('direct') else 'other/none'}</td>"
        f"<td>{i.get('tls', {}).get('cert_days_left', '-')}</td><td>{'yes' if i.get('http', {}).get('http_redirect') else 'no'}</td>"
        f"<td>{i.get('http', {}).get('https_status', '-')}</td><td>{'yes' if i.get('http', {}).get('security_txt') else 'no'}</td><td>{badge(h)}</td></tr>"
        for h, i in sorted(hosts_info.items()))
    mail_rows = ''.join(
        f"<tr><td>{e(d)}</td><td>{'yes' if m['mx'] else 'no'}</td><td>{e(m['spf'][0][:60]) if m['spf'] else '<b style=color:#b91c1c>missing</b>'}</td>"
        f"<td>{e(m['dmarc'][0][:70]) if m['dmarc'] else '<b style=color:#b91c1c>missing</b>'}</td><td>{'yes' if m['dkim_mail_selector'] else 'no'}</td><td>{badge(d)}</td></tr>"
        for d, m in sorted(mail_info.items()))
    exposed = host_info.get('internet_exposed', {})
    exp_rows = ''.join(f"<li><b>{e(p)}</b> {e(proc)}</li>" for p, proc in exposed.items()) or '<li>none beyond web + mail</li>'
    allow = host_info.get('allowlisted_ports', {})
    allow_rows = ''.join(f"<li>{e(p)} → only from {e(', '.join(s))}</li>" for p, s in allow.items()) or '<li>none</li>'
    resolved_rows = ''.join(f"<li>{e(f['target'])}: {e(f['title'])}</li>" for f in resolved) or '<li>nothing changed</li>'
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Security review {e(stamp)}</title>
<style>
:root{{--bg:#f8fafc;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:28px 16px}} h1{{margin:0 0 4px;font-size:26px}} h2{{margin:32px 0 10px;font-size:19px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}} .card b{{font-size:26px;display:block}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:14px}} th{{background:#f1f5f9}}
.pill{{color:#fff;border-radius:999px;padding:2px 9px;font-size:12px;font-weight:600;text-transform:uppercase}} .new{{color:#b91c1c;font-weight:700;font-size:12px}}
.muted{{color:var(--muted);font-size:13px}} .fix{{color:#334155;font-size:13px}} ul{{margin:6px 0}} .foot{{color:var(--muted);font-size:13px;margin-top:30px}}
</style></head><body><main>
<h1>Security review — {e(stamp)}</h1>
<div class=muted>Server {SERVER_IP} · {len(hosts_info)} hostnames · {len(mail_info)} mail domains · checklist: Everyday Security</div>
<div class=cards>
<div class=card>Critical<b style="color:#b91c1c">{counts['critical']}</b></div><div class=card>High<b style="color:#c2410c">{counts['high']}</b></div>
<div class=card>Medium<b style="color:#a16207">{counts['medium']}</b></div><div class=card>Low<b style="color:#1d4ed8">{counts['low']}</b></div>
<div class=card>New since last run<b>{len(new_keys)}</b></div><div class=card>Open tickets<b>{open_tickets}</b></div></div>
<h2>Findings</h2><table><tr><th>Severity</th><th>Where</th><th>What</th><th>Fix</th></tr>{rows or '<tr><td colspan=4>No findings.</td></tr>'}</table>
<h2>Resolved since last run</h2><ul>{resolved_rows}</ul>
<h2>What the internet can reach on this server</h2><ul>{exp_rows}</ul>
<div class=muted>Ports open only to specific IPs (your allow-list):</div><ul>{allow_rows}</ul>
<h2>Hostnames</h2><table><tr><th>Host</th><th>Served via</th><th>Cert days left</th><th>HTTP→HTTPS</th><th>HTTPS status</th><th>security.txt</th><th>Worst</th></tr>{host_rows}</table>
<h2>Mail domains</h2><table><tr><th>Domain</th><th>MX</th><th>SPF</th><th>DMARC</th><th>DKIM (mail)</th><th>Worst</th></tr>{mail_rows}</table>
<p class=foot>Read-only review of our own properties. History: /var/lib/security-review (git). Tickets: /var/lib/security-review/tickets. Re-run: sudo python3 /opt/security-review/security_review.py</p>
</main></body></html>"""


def send_status_mail(stamp: str, new_sig: list[dict], run_dir: str, open_tickets: int):
    lines = [f'Security review {stamp}: {len(new_sig)} new finding(s) need attention.', '']
    for f in sorted(new_sig, key=lambda x: SEVERITY_ORDER[x['severity']]):
        lines.append(f"[{f['severity'].upper()}] {f['target']}: {f['title']}\n    {f['detail']}\n    Fix: {f['fix']}")
    lines += ['', f'Open tickets: {open_tickets}', f'Full report (HTML): {run_dir}/report.html', 'Tickets: /var/lib/security-review/tickets/open/', '', 'This is an automated status from the monthly/weekly security review. Nothing was changed on the server.', 'Profitell Security Consulting']
    body = '\n'.join(lines)
    msg = f"From: Security Review <{FROM_EMAIL}>\nTo: {OWNER_EMAIL}\nSubject: [Security review] {len(new_sig)} new finding(s) need attention ({stamp})\nContent-Type: text/plain; charset=UTF-8\n\n{body}\n"
    subprocess.run(['/usr/sbin/sendmail', '-t', '-f', FROM_EMAIL], input=msg.encode(), timeout=30)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--no-mail', action='store_true'); ap.add_argument('--hosts', help='comma list to limit (testing)')
    a = ap.parse_args()
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d_%H%M')
    run_dir = os.path.join(RUNS, stamp); os.makedirs(run_dir, exist_ok=True)
    hosts = a.hosts.split(',') if a.hosts else discover_hosts()
    hosts_info = {}
    for h in hosts:
        info = {'dns': check_dns(h)}
        resolvable = bool(info['dns']['a'] or info['dns']['aaaa'] or info['dns']['cname'])
        info['tls'] = check_tls(h, resolvable); info['http'] = check_http(h, resolvable)
        hosts_info[h] = info
        print(f'  checked {h}', file=sys.stderr)
    mail_info = {d: check_mail_domain(d) for d in sorted({apex(h) for h in hosts})}
    host_info = check_host()
    findings = [f.d() for f in F]
    prev = load_previous(RUNS, stamp)
    prev_keys = {f['key'] for f in prev['findings']} if prev else set()
    cur_keys = {f['key'] for f in findings}
    new_keys = cur_keys - prev_keys if prev else set()
    resolved = [f for f in prev['findings'] if f['key'] not in cur_keys] if prev else []
    opened, closed = update_tickets(findings, stamp)
    open_tickets = len(os.listdir(os.path.join(TICKETS, 'open')))
    json.dump({'stamp': stamp, 'hosts': hosts_info, 'mail': mail_info, 'host': host_info, 'findings': findings, 'new': sorted(new_keys), 'resolved': [f['key'] for f in resolved], 'tickets_opened': opened, 'tickets_closed': closed},
              open(os.path.join(run_dir, 'findings.json'), 'w', encoding='utf8'), indent=1, default=str)
    open(os.path.join(run_dir, 'report.html'), 'w', encoding='utf8').write(render_html(stamp, hosts_info, mail_info, host_info, findings, new_keys, resolved, open_tickets))
    counts = defaultdict(int)
    for f in findings: counts[f['severity']] += 1
    summary = [f'# Security review {stamp}', '', f"critical {counts['critical']} · high {counts['high']} · medium {counts['medium']} · low {counts['low']} · info {counts['info']} · new {len(new_keys)} · resolved {len(resolved)} · open tickets {open_tickets}", '']
    for f in sorted(findings, key=lambda x: (SEVERITY_ORDER[x['severity']], x['target'])):
        if f['severity'] in ('critical', 'high', 'medium'):
            summary.append(f"- [{f['severity']}]{' NEW' if f['key'] in new_keys else ''} {f['target']}: {f['title']}")
    open(os.path.join(run_dir, 'summary.md'), 'w', encoding='utf8').write('\n'.join(summary) + '\n')
    latest = os.path.join(BASE, 'latest')
    if os.path.islink(latest) or os.path.exists(latest): os.remove(latest)
    os.symlink(run_dir, latest)
    new_sig = [f for f in findings if f['key'] in new_keys and significant(f)]
    if prev is None:
        print('baseline run: no comparison, no e-mail', file=sys.stderr)
    elif new_sig and not a.no_mail:
        send_status_mail(stamp, new_sig, run_dir, open_tickets); print(f'status e-mail sent ({len(new_sig)} new significant)', file=sys.stderr)
    else:
        print('nothing new that needs attention: no e-mail', file=sys.stderr)
    if os.path.isdir(os.path.join(BASE, '.git')):
        subprocess.run(['git', '-C', BASE, 'add', '-A'], capture_output=True)
        subprocess.run(['git', '-C', BASE, '-c', 'user.name=security-review', '-c', 'user.email=security-review@localhost', 'commit', '-q', '-m', f'review {stamp}: {len(findings)} findings, {len(new_keys)} new, {len(resolved)} resolved'], capture_output=True)
    print('\n'.join(summary))
    print(f'\nreport: {run_dir}/report.html')


if __name__ == '__main__':
    main()
