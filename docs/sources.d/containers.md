# Sources: containers and Docker (pillar `containers`)

URLs were fetched on 2026-11-09 and returned HTTP 200. All are public standards or primary documentation; checks cite them and are written in our own words. Sources already defined in `../sources.md` or other ledgers (for example S-DOCKER-SECURITY, S-DOCKER-PORTS, S-DOCKER-FIREWALL, S-DOCKER-JSONFILE, S-TRIVY-IMAGE, S-OWASP-SECRETS, S-OWASP-A06, S-CIS-BENCH) are reused, not redefined.

| ID | Source | Publisher | URL | Usage note |
|---|---|---|---|---|
| S-NIST80190 | SP 800-190: Application Container Security Guide | NIST | https://csrc.nist.gov/pubs/sp/800/190/final | cite only; image, registry, orchestrator, container and host-OS risk areas |
| S-OWASP-CS-DOCKER | Docker Security Cheat Sheet | OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html | CC BY-SA 4.0; cite only |
| S-CIS-DOCKER | CIS Docker Benchmark (landing page) | Center for Internet Security | https://www.cisecurity.org/benchmark/docker | Named for orientation only; licence forbids reuse, no items reproduced. |
| S-DOCKER-POSTINSTALL | Linux post-installation steps for Docker Engine | Docker Inc. | https://docs.docker.com/engine/install/linux-postinstall/ | The docker group and its access to the daemon socket |
| S-DOCKER-ROOTLESS | Rootless mode | Docker Inc. | https://docs.docker.com/engine/security/rootless/ | Running the daemon and containers without host root |
| S-DOCKER-USERNS | Isolate containers with a user namespace | Docker Inc. | https://docs.docker.com/engine/security/userns-remap/ | Remapping container root to an unprivileged host user |
| S-DOCKER-TRUSTED | Docker Hub trusted content | Docker Inc. | https://docs.docker.com/docker-hub/image-library/trusted-content/ | Official Images, Verified Publisher and similar categories |
| S-DOCKER-BESTPRACTICES | Building best practices | Docker Inc. | https://docs.docker.com/build/building/best-practices/ | Pinning base image versions and digests; USER instruction; multi-stage builds |
| S-DOCKER-SCOUT | Docker Scout | Docker Inc. | https://docs.docker.com/scout/ | Image analysis and vulnerability reporting |
| S-DOCKER-RUN | docker container run reference | Docker Inc. | https://docs.docker.com/reference/cli/docker/container/run/ | Flags such as --user, --cap-drop, --read-only, --security-opt, --memory, --pids-limit |
| S-DOCKER-INSPECT | docker container inspect reference | Docker Inc. | https://docs.docker.com/reference/cli/docker/container/inspect/ | Reading effective container settings with --format |
| S-DOCKER-COMPOSE-SERVICES | Compose file reference: services | Docker Inc. | https://docs.docker.com/reference/compose-file/services/ | user, cap_drop, read_only, security_opt, healthcheck, mem_limit, pids_limit, restart, logging |
| S-DOCKER-COMPOSE-CONFIG | docker compose config reference | Docker Inc. | https://docs.docker.com/reference/cli/docker/compose/config/ | Rendering the effective, merged Compose model for review |
| S-DOCKER-COMPOSE-SECRETS | How to use secrets in Docker Compose | Docker Inc. | https://docs.docker.com/compose/how-tos/use-secrets/ | Secrets mounted as files; risks of environment variables |
| S-DOCKER-RESOURCES | Resource constraints | Docker Inc. | https://docs.docker.com/engine/containers/resource_constraints/ | Memory and CPU limits, out-of-memory behaviour |
| S-DOCKER-NETWORKING | Networking overview | Docker Inc. | https://docs.docker.com/engine/network/ | User-defined networks and container isolation |
| S-DOCKER-BRIDGE | Bridge network driver | Docker Inc. | https://docs.docker.com/engine/network/drivers/bridge/ | Default bridge versus user-defined bridge; inter-container connectivity options |
| S-DOCKER-VOLUMES | Volumes | Docker Inc. | https://docs.docker.com/engine/storage/volumes/ | Where persistent data lives; backing up and restoring volumes |
| S-DOCKER-LOGGING | Configure logging drivers | Docker Inc. | https://docs.docker.com/engine/logging/configure/ | Default logging driver and how to change it |
| S-DOCKER-LIVERESTORE | Live restore | Docker Inc. | https://docs.docker.com/engine/daemon/live-restore/ | Keeping containers running while the daemon restarts for an upgrade |
| S-DOCKER-RELEASES | Docker Engine release notes | Docker Inc. | https://docs.docker.com/engine/release-notes/ | Tracking engine versions and fixes |
| S-TRIVY-FILTER | Trivy: Filtering | Aqua Security | https://trivy.dev/latest/docs/configuration/filtering/ | Severity filter, --ignore-unfixed and the ignore file used for triage decisions |
