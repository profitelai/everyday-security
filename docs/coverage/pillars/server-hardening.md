# Server hardening

[← Coverage](../README.md)

SSH, firewall, listening ports, patching, fail2ban, clock, file permissions, certificate renewal.

**12 checks** · 0 run automatically · 8 in the server audit · 4 guided checklists · for: Linux servers you administer

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [SRV-001](../../kb/server-hardening/SRV-001.md) | SSH login policy is a deliberate, documented decision with compensating controls | high | Server audit | NIST SP 800-123, OpenSSH sshd_config(5) |
| [SRV-002](../../kb/server-hardening/SRV-002.md) | The host firewall denies inbound traffic by default and opens only needed ports | high | Server audit | NIST SP 800-123 |
| [SRV-003](../../kb/server-hardening/SRV-003.md) | Only needed services listen, and databases and caches listen on localhost | high | Server audit | NIST SP 800-123 |
| [SRV-004](../../kb/server-hardening/SRV-004.md) | Docker published ports are controlled and do not silently bypass the host firewall | high | Server audit | NIST SP 800-123 |
| [SRV-005](../../kb/server-hardening/SRV-005.md) | Security updates install automatically and pending reboots are handled | high | Server audit | NIST SP 800-123 |
| [SRV-006](../../kb/server-hardening/SRV-006.md) | Repeated failed logins are blocked automatically without locking out the administrator | medium | Server audit | NIST SP 800-123 |
| [SRV-007](../../kb/server-hardening/SRV-007.md) | Services and containers run as unprivileged users with least privilege | medium | Guided checklist | NIST SP 800-123 |
| [SRV-008](../../kb/server-hardening/SRV-008.md) | Web roots, config files and keys have tight ownership and permissions, and no secrets sit in the web root | high | Server audit | NIST SP 800-123 |
| [SRV-009](../../kb/server-hardening/SRV-009.md) | Secrets are kept out of repositories and dumps, and rotated after any exposure | high | Guided checklist | OWASP Secrets Management Cheat Sheet |
| [SRV-010](../../kb/server-hardening/SRV-010.md) | The clock is synchronized and logs are rotated, bounded and retained deliberately | medium | Server audit | NIST SP 800-92, NIST SP 800-123 |
| [SRV-011](../../kb/server-hardening/SRV-011.md) | Installed packages, dependencies and container images are scanned for known vulnerabilities on a schedule | medium | Guided checklist | NIST SP 800-123 |
| [SRV-012](../../kb/server-hardening/SRV-012.md) | Alerts for outages, full disks and failed jobs reach a person who actually reads them | medium | Guided checklist | NIST SP 800-92, NIST SP 800-123 |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
