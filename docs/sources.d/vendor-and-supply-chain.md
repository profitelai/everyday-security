# Sources: vendors and software supply chain (pillar `vendor-and-supply-chain`)

URLs were fetched on 2026-11-09 and returned HTTP 200. All are public standards or primary documentation; checks cite them and are written in our own words. IDs already defined in other ledgers (for example S-OWASP-CS-DEPS, S-NPM-AUDIT, S-OWASP-SECRETS, S-OPC-PIPEDA-BRIEF) are reused, not redefined.

| ID | Source | Publisher | URL | Usage note |
|---|---|---|---|---|
| S-NIST80161 | SP 800-161 Rev. 1: Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations | NIST | https://csrc.nist.gov/pubs/sp/800/161/r1/final | cite only; written for large organizations, we scale the ideas down |
| S-NIST80218 | SP 800-218: Secure Software Development Framework (SSDF) Version 1.1 | NIST | https://csrc.nist.gov/pubs/sp/800/218/final | cite only; practices on reusing third-party components |
| S-CCCS-SUPPLY | Cyber supply chain security for small and medium-sized organizations (ITSAP.00.070) | Canadian Centre for Cyber Security | https://www.cyber.gc.ca/en/guidance/cyber-supply-chain-security-small-medium-sized-organizations-itsap00070 | cite only; vendor inventory, classification, contract notification clauses, re-evaluation |
| S-OPC-OUTSOURCING | Guidelines for processing personal data across borders | Office of the Privacy Commissioner of Canada | https://www.priv.gc.ca/en/privacy-topics/airports-and-borders/gl_dab_090127/ | cite only; accountability stays with the transferring organization (older guidance, checked against PIPEDA) |
| S-CISA-SBOM | Software Bill of Materials (SBOM) | CISA | https://www.cisa.gov/sbom | cite only |
| S-NTIA-SBOM | The Minimum Elements For a Software Bill of Materials (SBOM) | NTIA | https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom | cite only |
| S-CYCLONEDX | CycloneDX bill of materials specification | OWASP / Ecma | https://cyclonedx.org/ | cite only |
| S-SPDX | SPDX specification | Linux Foundation | https://spdx.dev/ | cite only |
| S-SYFT | Syft: SBOM generator | Anchore | https://github.com/anchore/syft | cite only; open-source tool documentation |
| S-CISA-KEV | Known Exploited Vulnerabilities Catalog | CISA | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | cite only |
| S-OPENSSF-SCORECARD | OpenSSF Scorecard | OpenSSF | https://scorecard.dev/ | cite only |
| S-OPENSSF-SCORECARD-CLI | ossf/scorecard repository (checks and command-line usage) | OpenSSF | https://github.com/ossf/scorecard | cite only |
| S-SLSA | SLSA: Supply-chain Levels for Software Artifacts | OpenSSF | https://slsa.dev/ | cite only; used for ideas, not as a requirement for small teams |
| S-OWASP-CS-NPM | NPM Security Cheat Sheet | OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html | CC BY-SA 4.0; cite only |
| S-OWASP-CS-CICD | CI/CD Security Cheat Sheet | OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html | CC BY-SA 4.0; cite only |
| S-OWASP-CS-SSC | Software Supply Chain Security Cheat Sheet | OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html | CC BY-SA 4.0; cite only |
| S-OWASP-CS-3PJS | Third Party JavaScript Management Cheat Sheet | OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html | CC BY-SA 4.0; cite only |
| S-W3C-SRI | Subresource Integrity | W3C | https://www.w3.org/TR/SRI/ | cite only |
| S-MDN-SRI | Subresource Integrity | MDN Web Docs | https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity | CC BY-SA; cite only |
| S-GITHUB-DEPENDABOT | Dependabot version updates | GitHub Docs | https://docs.github.com/en/code-security/dependabot/dependabot-version-updates | cite only |
| S-RENOVATE | Renovate documentation | Renovate | https://docs.renovatebot.com/ | cite only |
| S-NPM-CI | npm ci | npm, Inc. | https://docs.npmjs.com/cli/v10/commands/npm-ci | cite only |
| S-NPM-CONFIG | npm config (ignore-scripts and other settings) | npm, Inc. | https://docs.npmjs.com/cli/v10/using-npm/config | cite only |
| S-PIP-SECURE | Secure installs | Python Packaging Authority (pip) | https://pip.pypa.io/en/stable/topics/secure-installs/ | cite only; hash-checking mode |
| S-GITHUB-ACTIONS-HARDENING | Security hardening for GitHub Actions | GitHub Docs | https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions | cite only |
| S-AICPA-SOC | SOC 2 (System and Organization Controls) overview | AICPA & CIMA | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | cite only; explains the report family, not its contents |
