"""Read-only audit of the machine it runs on (Linux servers). Judges the server-hardening checks that cannot be seen from outside.
Every collector only READS state (no changes, no network calls). Parsers are pure functions so they can be tested with fixtures.
Statuses follow the same model as website scans: PASS, WARN, FAIL, MANUAL (could not read or needs a human), INFO."""
import glob, os, re, shutil, stat, subprocess, time

HOST_IDS = ("SRV-001", "SRV-002", "SRV-003", "SRV-004", "SRV-005", "SRV-006", "SRV-008", "SRV-010", "TLS-006")
DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 11211: "Memcached", 9200: "Elasticsearch", 5984: "CouchDB"}

# ---------- pure parsers ----------

def parse_sshd(text):
    """Lowercased key -> value from `sshd -T` output (first value wins)."""
    d = {}
    for l in text.splitlines():
        k, _, v = l.strip().partition(" ")
        if k and k.lower() not in d: d[k.lower()] = v.strip().lower()
    return d

def judge_ssh(d):
    if not d: return "MANUAL", "could not read sshd configuration (run as root: sshd -T)"
    root, pw = d.get("permitrootlogin", "?"), d.get("passwordauthentication", "?")
    bad = []
    if root in ("yes",): bad.append("root login with a password is allowed")
    if pw == "yes": bad.append("password logins are allowed")
    detail = f"PermitRootLogin {root}; PasswordAuthentication {pw}; port {d.get('port', '?')}"
    if root == "yes" and pw == "yes": return "FAIL", detail
    if bad: return "WARN", detail + " (acceptable only as a documented decision with a brute-force blocker such as fail2ban)"
    return "PASS", detail

def parse_listeners(text):
    """Rows of (proto, address, port) from `ss -lntuH` output."""
    out = []
    for l in text.splitlines():
        p = l.split()
        if len(p) < 5: continue
        local = p[4]; addr, _, port = local.rpartition(":")
        if port.isdigit(): out.append((p[0], addr.strip("[]"), int(port)))
    return out

def judge_listeners(rows):
    exposed = sorted({(DB_PORTS[port], addr, port) for _, addr, port in rows if port in DB_PORTS and addr not in ("127.0.0.1", "::1", "localhost")})
    pub = sorted({port for _, addr, port in rows if addr in ("0.0.0.0", "*", "::", "")})
    if exposed: return "FAIL", "database or cache reachable beyond localhost: " + ", ".join(f"{n} on {a}:{p}" for n, a, p in exposed)
    return "PASS", f"{len(pub)} port(s) listen on all interfaces: {', '.join(map(str, pub[:15])) or 'none'}; no database or cache is exposed (confirm each public port is intended)"

def judge_firewall(ufw, nft, ipt):
    if re.search(r"Status:\s*active", ufw or ""):
        pol = re.search(r"Default:\s*(\w+) \(incoming\)", ufw or "")
        return ("PASS" if pol and pol.group(1) in ("deny", "reject") else "FAIL"), f"ufw active, default incoming {pol.group(1) if pol else '?'}"
    if re.search(r"policy drop", nft or "", re.I): return "PASS", "nftables has a drop policy"
    if re.search(r"^-P INPUT (DROP|REJECT)", ipt or "", re.M): return "PASS", "iptables INPUT policy is DROP/REJECT"
    if not (ufw or nft or ipt): return "MANUAL", "no firewall tool could be read (run as root)"
    return "FAIL", "no default-deny host firewall found"

def parse_docker_ports(text):
    """From `docker ps --format '{{.Names}}\t{{.Ports}}'`: [(name, port)] for ports published on all interfaces."""
    out = []
    for l in text.splitlines():
        name, _, ports = l.partition("\t")
        for m in re.finditer(r"(?:0\.0\.0\.0|\[::\]|:::)(?::)?(\d+)->", ports): out.append((name, int(m.group(1))))
    return out

def judge_docker(rows):
    if rows is None: return "INFO", "Docker not present or not readable"
    risky = [(n, p) for n, p in rows if p in DB_PORTS]; other = len(rows) - len(risky)
    if risky: return "FAIL", "containers publish database or cache ports on all interfaces: " + ", ".join(f"{n}:{p}" for n, p in risky)
    return ("WARN" if other else "PASS"), (f"{other} container port(s) published on all interfaces: " + ", ".join(f"{n}:{p}" for n, p in rows[:8]) + ". Docker bypasses ufw, so bind to 127.0.0.1 unless public on purpose") if other else "no container ports published on all interfaces"

def judge_updates(unattended_on, reboot_required, pending):
    d = f"unattended-upgrades {'enabled' if unattended_on else 'not enabled'}; reboot {'required' if reboot_required else 'not required'}; {pending if pending is not None else '?'} pending package updates"
    if not unattended_on: return "FAIL", d
    if reboot_required or (pending or 0) > 25: return "WARN", d
    return "PASS", d

def judge_bruteforce(out):
    if out is None: return "MANUAL", "fail2ban-client not readable (is it installed? run as root)"
    jails = re.search(r"Jail list:\s*(.*)", out)
    names = [j.strip() for j in jails.group(1).split(",") if j.strip()] if jails else []
    return ("PASS" if names else "WARN"), f"fail2ban jails: {', '.join(names) or 'none'}"

def judge_time(out):
    if out is None: return "MANUAL", "timedatectl not available"
    ok = re.search(r"System clock synchronized:\s*yes", out) or re.search(r"NTP synchronized:\s*yes", out)
    return ("PASS" if ok else "FAIL"), "clock is synchronized" if ok else "clock is not synchronized (enable systemd-timesyncd or chrony)"

def judge_perms(findings):
    if findings is None: return "MANUAL", "could not scan web roots"
    return ("FAIL" if findings else "PASS"), ("; ".join(findings[:8]) + (f" (+{len(findings) - 8} more)" if len(findings) > 8 else "")) if findings else "no world-writable files or world-readable secret files found in the web roots checked"

def judge_certbot(timers, renew_conf_count):
    if renew_conf_count == 0 and not timers: return "MANUAL", "no certbot renewal configs found (certificates may be managed elsewhere: CDN, Caddy, acme.sh)"
    return ("PASS" if timers else "WARN"), f"{renew_conf_count} certbot renewal config(s); renewal timer {'active' if timers else 'NOT found'}"

# ---------- collectors (read-only) ----------

def _run(cmd, timeout=20):
    if not shutil.which(cmd[0]): return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 or r.stdout else None
    except Exception: return None

def find_perm_issues(roots=("/var/www", "/srv/www", "/home/*/public_html"), limit=200):
    out, seen = [], 0
    secret = re.compile(r"(^|/)(\.env(\..*)?|wp-config\.php|config\.php|\.htpasswd|id_rsa|.*\.pem|.*\.key|.*\.sql|.*\.bak)$")
    for pat in roots:
        for root in glob.glob(pat):
            for dp, dn, fn in os.walk(root):
                dn[:] = [d for d in dn if d not in ("node_modules", ".git", "vendor", "cache")]
                for f in fn:
                    seen += 1
                    if seen > 50000: return out
                    p = os.path.join(dp, f)
                    try: m = os.lstat(p).st_mode
                    except OSError: continue
                    if stat.S_ISLNK(m): continue
                    if m & stat.S_IWOTH: out.append(f"world-writable {p}")
                    elif secret.search(p) and m & stat.S_IROTH and not p.endswith((".pub",)): out.append(f"world-readable secret-like file {p}")
                    if len(out) >= limit: return out
    return out

def run_audit():
    """Returns [(check_id, status, detail)] for the server-hardening checks this host can judge, plus TLS-006."""
    res = []
    res.append(("SRV-001",) + judge_ssh(parse_sshd(_run(["sshd", "-T"]) or "")))
    ss = _run(["ss", "-lntuH"]); res.append(("SRV-003",) + (judge_listeners(parse_listeners(ss)) if ss else ("MANUAL", "ss not available")))
    res.append(("SRV-002",) + judge_firewall(_run(["ufw", "status", "verbose"]) or "", _run(["nft", "list", "ruleset"]) or "", _run(["iptables", "-S"]) or ""))
    dk = _run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"]); res.append(("SRV-004",) + judge_docker(None if dk is None else parse_docker_ports(dk)))
    cfg = (open("/etc/apt/apt.conf.d/20auto-upgrades").read() if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades") else "")
    on = bool(re.search(r'Unattended-Upgrade\s+"1"', cfg)); pend = None
    sim = _run(["apt-get", "-s", "upgrade"], timeout=60)
    if sim: pend = len(re.findall(r"^Inst ", sim, re.M))
    res.append(("SRV-005",) + (judge_updates(on, os.path.exists("/var/run/reboot-required"), pend) if os.path.isdir("/etc/apt") else ("MANUAL", "not a Debian or Ubuntu host: check your distribution's automatic security update tool (dnf-automatic, etc.)")))
    res.append(("SRV-006",) + judge_bruteforce(_run(["fail2ban-client", "status"])))
    res.append(("SRV-008",) + judge_perms(find_perm_issues() if any(glob.glob(r) for r in ("/var/www", "/srv/www", "/home/*/public_html")) else None))
    res.append(("SRV-010",) + judge_time(_run(["timedatectl", "status"])))
    timers = bool(re.search(r"certbot|acme", _run(["systemctl", "list-timers", "--all", "--no-pager"]) or "", re.I))
    res.append(("TLS-006",) + judge_certbot(timers, len(glob.glob("/etc/letsencrypt/renewal/*.conf"))))
    return res

def audit_result(host_label="this-server"):
    """A result dict shaped like a site result so reports, history and diffs work unchanged."""
    from . import registry
    from .model import score, tally
    checks = registry.load_checks(); results = []
    for cid, status, detail in run_audit():
        m = checks.get(cid, {})
        results.append({"id": cid, "status": status, "detail": detail, "severity": m.get("severity", "info"), "title": m.get("title", cid), "pillar": m.get("pillar", "server-hardening"), "tags": m.get("tags", []), "kb": m.get("file"), "source_type": "host"})
    s, g = score(results)
    return {"host": host_label, "name": host_label, "tags": ["server"], "owner": "", "criticality": "", "deep": False, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": 0, "score": s, "grade": g, "tally": tally(results), "rules": {"evaluated": 0, "hits": 0, "skipped": 0, "expired": 0}, "results": results}
