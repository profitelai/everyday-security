# Sources: server-hardening pillar

Primary documentation and public publications only. Text in the checks is our own wording; nothing is copied. CIS Benchmarks are named for orientation only (restrictive licence): none of their items are reproduced or closely paraphrased. OWASP cheat sheets are CC BY-SA 4.0: cited, not copied. URLs checked 2026-11-09 (HTTP 200).

| ID | Source | Publisher | URL | Usage note |
|---|---|---|---|---|
| S-SSHD-CONFIG | sshd_config(5) manual | OpenBSD / OpenSSH | https://man.openbsd.org/sshd_config | Option names and upstream defaults for SSH hardening (SRV-001). |
| S-SSH-KEYGEN | ssh-keygen(1) manual | OpenBSD / OpenSSH | https://man.openbsd.org/ssh-keygen | Listing key fingerprints in authorized_keys (SRV-001). |
| S-SYSTEMD-RUN | systemd-run manual | systemd project | https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html | Transient timer used as an automatic revert (SRV-001, SRV-002, SRV-004). |
| S-SYSTEMD-EXEC | systemd.exec manual | systemd project | https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html | User=, sandboxing and EnvironmentFile= directives (SRV-007, SRV-009). |
| S-SYSTEMD-ANALYZE | systemd-analyze manual | systemd project | https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html | `systemd-analyze security` exposure report (SRV-007). |
| S-SYSTEMD-UNIT | systemd.unit manual | systemd project | https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html | OnFailure= handlers for failed units (SRV-012). |
| S-NIST-800-123 | SP 800-123, Guide to General Server Security | NIST | https://csrc.nist.gov/pubs/sp/800/123/final | General server hardening principles; cited as background, not reproduced. |
| S-NIST-800-92 | SP 800-92, Guide to Computer Security Log Management | NIST | https://csrc.nist.gov/pubs/sp/800/92/final | Log management and monitoring background (SRV-010, SRV-012). |
| S-CIS-BENCH | CIS Benchmarks (Linux distributions) | Center for Internet Security | https://www.cisecurity.org/cis-benchmarks | Named for orientation only; licence forbids reuse, no items reproduced. |
| S-UBUNTU-FIREWALL | Firewalls (ufw), Ubuntu Server documentation | Canonical | https://ubuntu.com/server/docs/how-to/security/firewalls/ | ufw usage, dry-run, and Docker/ufw note (SRV-002, SRV-004). |
| S-UFW-MAN | ufw(8) manual page (Ubuntu 24.04) | Canonical | https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html | ufw defaults and rule syntax (SRV-002). |
| S-SS-MAN | ss(8) manual page | Linux man-pages project | https://man7.org/linux/man-pages/man8/ss.8.html | Flags for listing listening sockets (SRV-002, SRV-003). |
| S-PG-CONN | PostgreSQL docs, Connections and Authentication settings | PostgreSQL Global Development Group | https://www.postgresql.org/docs/current/runtime-config-connection.html | listen_addresses and its localhost default (SRV-003). |
| S-REDIS-SEC | Redis security | Redis Ltd. | https://redis.io/docs/latest/operate/oss_and_stack/management/security/ | Binding to loopback and protected mode (SRV-003). |
| S-DOCKER-FIREWALL | Packet filtering and firewalls | Docker Inc. | https://docs.docker.com/engine/network/packet-filtering-firewalls/ | Docker and ufw interaction; risks of disabling iptables management (SRV-004). |
| S-DOCKER-PORTS | Port publishing and mapping | Docker Inc. | https://docs.docker.com/engine/network/port-publishing/ | Default publish to all addresses; binding to 127.0.0.1 (SRV-004). |
| S-DOCKER-IPTABLES | Docker with iptables | Docker Inc. | https://docs.docker.com/engine/network/firewall-iptables/ | The DOCKER-USER chain and how rules there match (SRV-004). |
| S-DOCKER-SECURITY | Docker Engine security | Docker Inc. | https://docs.docker.com/engine/security/ | Daemon attack surface and docker group privileges (SRV-007). |
| S-DOCKER-JSONFILE | JSON File logging driver | Docker Inc. | https://docs.docker.com/engine/logging/drivers/json-file/ | max-size and max-file; default is unlimited (SRV-010). |
| S-UBUNTU-AUTOUPDATE | Automatic updates, Ubuntu Server documentation | Canonical | https://documentation.ubuntu.com/server/how-to/software/automatic-updates/ | unattended-upgrades options, reboot settings, needrestart (SRV-005). |
| S-DEBIAN-UNATTENDED | UnattendedUpgrades, Debian Wiki | Debian project | https://wiki.debian.org/UnattendedUpgrades | Debian setup, local override file, apt-daily timers (SRV-005). |
| S-FAIL2BAN-JAIL | jail.conf(5) manual page | fail2ban project (Debian manpages) | https://manpages.debian.org/stable/fail2ban/jail.conf.5.en.html | ignoreip, ignoreself, bantime, findtime, maxretry (SRV-006). |
| S-FAIL2BAN-CLIENT | fail2ban-client(1) manual page | fail2ban project (Debian manpages) | https://manpages.debian.org/stable/fail2ban/fail2ban-client.1.en.html | status, get and set commands, unbanip (SRV-006). |
| S-PHP-FPM-CONF | PHP manual, FPM configuration | The PHP Group | https://www.php.net/manual/en/install.fpm.configuration.php | Pool user and group settings (SRV-007). |
| S-FIND-MAN | find(1) manual page | Linux man-pages project | https://man7.org/linux/man-pages/man1/find.1.html | -perm and -printf usage for permission audits (SRV-008). |
| S-OWASP-SECRETS | Secrets Management Cheat Sheet | OWASP | https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html | Background on storage and rotation of secrets (SRV-008, SRV-009); CC BY-SA 4.0, cited not copied. |
| S-TIMEDATECTL | timedatectl manual | systemd project | https://www.freedesktop.org/software/systemd/man/latest/timedatectl.html | Clock and NTP status (SRV-010). |
| S-TIMESYNCD | systemd-timesyncd.service manual | systemd project | https://www.freedesktop.org/software/systemd/man/latest/systemd-timesyncd.service.html | Lightweight SNTP client (SRV-010). |
| S-CHRONY | chrony documentation | chrony project | https://chrony-project.org/documentation.html | chrony as the full NTP client (SRV-010). |
| S-LOGROTATE | logrotate(8) manual page | Linux man-pages project | https://man7.org/linux/man-pages/man8/logrotate.8.html | Debug (dry-run) mode and rotation directives (SRV-010). |
| S-JOURNALD | journald.conf manual | systemd project | https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html | SystemMaxUse= and journal size limits (SRV-010). |
| S-TRIVY-ROOTFS | Trivy: Rootfs scanning | Aqua Security | https://trivy.dev/latest/docs/target/rootfs/ | Scanning a host root filesystem for OS package vulnerabilities (SRV-011). |
| S-TRIVY-FS | Trivy: Filesystem scanning | Aqua Security | https://trivy.dev/latest/docs/target/filesystem/ | Scanning application dependency lock files (SRV-011). |
| S-TRIVY-IMAGE | Trivy: Container image scanning | Aqua Security | https://trivy.dev/latest/docs/target/container_image/ | Scanning local container images (SRV-011). |
| S-DEBSECAN | debsecan(1) manual page | Debian project | https://manpages.debian.org/stable/debsecan/debsecan.1.en.html | Debian-only vulnerability listing for installed packages (SRV-011). |
