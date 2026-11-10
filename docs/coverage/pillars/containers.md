# Containers and Docker

[← Coverage](../README.md)

Image sources and tags, scanning, privileges, published ports, secrets, resource limits.

**11 checks** · 0 run automatically · 0 in the server audit · 11 guided checklists · for: Docker and Compose hosts

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [CTR-001](../../kb/containers/CTR-001.md) | Container images come from trusted sources and are pinned to a tag or digest | high | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet |
| [CTR-002](../../kb/containers/CTR-002.md) | Images are scanned for known vulnerabilities, findings are triaged by a written rule, and images are rebuilt regularly | high | Guided checklist | NIST SP 800-190, OWASP Top 10 A06:2021, OWASP Docker Security Cheat Sheet |
| [CTR-003](../../kb/containers/CTR-003.md) | Containers run as a non-root user | medium | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet |
| [CTR-004](../../kb/containers/CTR-004.md) | Containers are not privileged, drop capabilities, block privilege gain and use a read-only root filesystem where possible | high | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet, CIS Docker Benchmark |
| [CTR-005](../../kb/containers/CTR-005.md) | The Docker socket is never mounted into containers and the docker group is treated as root | critical | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet, CIS Docker Benchmark |
| [CTR-006](../../kb/containers/CTR-006.md) | Secrets are not baked into images or stored in Compose files and env files in git | high | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet |
| [CTR-007](../../kb/containers/CTR-007.md) | Containers have memory, CPU and process limits and a restart policy | medium | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet, CIS Docker Benchmark |
| [CTR-008](../../kb/containers/CTR-008.md) | Compose stacks are on separate networks and only the services that must talk to each other share one | medium | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet |
| [CTR-009](../../kb/containers/CTR-009.md) | Persistent container data is in known volumes that are included in backups and restore-tested | high | Guided checklist | NIST SP 800-190 |
| [CTR-010](../../kb/containers/CTR-010.md) | Containers have healthchecks and their logs are bounded, collected and watched | medium | Guided checklist | NIST SP 800-190, NIST SP 800-92 |
| [CTR-011](../../kb/containers/CTR-011.md) | The Docker engine and Compose are kept patched and the host runs a supported version | high | Guided checklist | NIST SP 800-190, OWASP Docker Security Cheat Sheet, CIS Docker Benchmark |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
