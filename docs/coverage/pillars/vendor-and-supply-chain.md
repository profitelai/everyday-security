# Vendors and supply chain

[← Coverage](../README.md)

Vendor inventory and contracts, dependencies, CI/CD pipelines, third-party scripts, exit plans.

**10 checks** · 0 run automatically · 0 in the server audit · 10 guided checklists · for: Any business and any developer

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [VEN-001](../../kb/vendor-and-supply-chain/VEN-001.md) | A vendor inventory records what data and access each supplier has, and ranks them by risk | high | Guided checklist | NIST SP 800-161 Rev. 1, Cyber Centre ITSAP.00.070 |
| [VEN-002](../../kb/vendor-and-supply-chain/VEN-002.md) | Critical vendors provide security evidence proportionate to their tier, and the evidence is read | medium | Guided checklist | NIST SP 800-161 Rev. 1, SOC 2, ISO/IEC 27001 |
| [VEN-003](../../kb/vendor-and-supply-chain/VEN-003.md) | Vendor contracts state breach notice, data location, sub-processors and exit terms | high | Guided checklist | NIST SP 800-161 Rev. 1, PIPEDA 4.1.3, Cyber Centre ITSAP.00.070 |
| [VEN-004](../../kb/vendor-and-supply-chain/VEN-004.md) | Someone is told when a critical vendor reports a security incident or an exploited flaw | medium | Guided checklist | NIST SP 800-161 Rev. 1, CISA KEV |
| [VEN-005](../../kb/vendor-and-supply-chain/VEN-005.md) | Dependencies are inventoried with committed lockfiles, pinned versions and a producible SBOM | medium | Guided checklist | NIST SP 800-218 (SSDF), NTIA SBOM minimum elements, OWASP Top 10:2021 A06 |
| [VEN-006](../../kb/vendor-and-supply-chain/VEN-006.md) | Dependency updates arrive as automated pull requests that a person reviews and tests | medium | Guided checklist | NIST SP 800-218 (SSDF), OWASP Top 10:2021 A06 |
| [VEN-007](../../kb/vendor-and-supply-chain/VEN-007.md) | New packages are vetted for typosquatting, install scripts and maintainer health before adoption | high | Guided checklist | NIST SP 800-218 (SSDF), OpenSSF Scorecard, OWASP NPM Security Cheat Sheet |
| [VEN-008](../../kb/vendor-and-supply-chain/VEN-008.md) | CI/CD pipelines use least-privilege, short-lived secrets and pinned third-party actions | high | Guided checklist | NIST SP 800-218 (SSDF), SLSA, OWASP CI/CD security |
| [VEN-009](../../kb/vendor-and-supply-chain/VEN-009.md) | Third-party scripts on the website are inventoried, integrity-checked where possible, and tag manager access is controlled | high | Guided checklist | W3C Subresource Integrity, OWASP Third Party JavaScript Management |
| [VEN-010](../../kb/vendor-and-supply-chain/VEN-010.md) | Every critical vendor has a tested exit plan: your own data copy, an alternative, and accounts you control | high | Guided checklist | NIST SP 800-161 Rev. 1, Cyber Centre ITSAP.00.070 |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
