# Cloud and SaaS accounts

[← Coverage](../README.md)

Admin accounts, MFA, OAuth grants, public storage, offboarding, account inventory.

**10 checks** · 0 run automatically · 0 in the server audit · 10 guided checklists · for: Teams using Google, Microsoft, AWS and similar

| ID | Check | Severity | How it is run | Standards |
|---|---|---|---|---|
| [CLD-001](../../kb/cloud-and-saas-accounts/CLD-001.md) | Every administrator account uses MFA, and the most powerful ones sign in with phishing-resistant methods | critical | Guided checklist | NIST SP 800-63B, NIST SP 800-53 IA-2, CIS Controls v8 6.5 |
| [CLD-002](../../kb/cloud-and-saas-accounts/CLD-002.md) | A tested break-glass path and business-owned recovery contacts exist for every critical account | high | Guided checklist | NIST SP 800-53 AC-2, NIST SP 800-53 CP-2, CIS Controls v8 5.4 |
| [CLD-003](../../kb/cloud-and-saas-accounts/CLD-003.md) | Admin rights are limited to named people with the narrowest role, and nobody shares an admin login | high | Guided checklist | NIST SP 800-53 AC-2, NIST SP 800-53 AC-5, NIST SP 800-53 AC-6, CIS Controls v8 5.4 |
| [CLD-004](../../kb/cloud-and-saas-accounts/CLD-004.md) | API keys and tokens are scoped, expire or are rotated, and are kept out of code repositories | high | Guided checklist | NIST SP 800-53 IA-5, NIST SP 800-53 SC-12, NIST SP 800-53 AC-6 |
| [CLD-005](../../kb/cloud-and-saas-accounts/CLD-005.md) | Leaving staff and contractors lose access to every cloud and SaaS account the same day | high | Guided checklist | NIST SP 800-53 PS-4, NIST SP 800-53 AC-2, CIS Controls v8 6.2 |
| [CLD-006](../../kb/cloud-and-saas-accounts/CLD-006.md) | Third-party app and OAuth grants to company data are limited and reviewed | medium | Guided checklist | NIST SP 800-53 AC-6, NIST SP 800-53 SA-9, CIS Controls v8 15.1 |
| [CLD-007](../../kb/cloud-and-saas-accounts/CLD-007.md) | Audit logging is on, kept long enough, and sign-in and admin-change alerts reach a person | medium | Guided checklist | NIST SP 800-53 AU-2, NIST SP 800-53 AU-6, NIST SP 800-53 SI-4, CIS Controls v8 8.2 |
| [CLD-008](../../kb/cloud-and-saas-accounts/CLD-008.md) | Public storage buckets and open sharing links are reviewed and blocked by default | high | Guided checklist | NIST SP 800-53 AC-3, NIST SP 800-53 AC-22, CIS Controls v8 3.3 |
| [CLD-009](../../kb/cloud-and-saas-accounts/CLD-009.md) | The DNS and CDN account and the domain registrar are locked down against takeover | high | Guided checklist | NIST SP 800-53 AC-2, NIST SP 800-53 IA-2, CIS Controls v8 6.5 |
| [CLD-010](../../kb/cloud-and-saas-accounts/CLD-010.md) | A short inventory lists every SaaS and cloud account with a named owner | medium | Guided checklist | NIST SP 800-53 CM-8, NIST SP 800-53 SA-9, CIS Controls v8 15.1 |

All checks are drafts (Alpha). Each check page explains why it matters, how to test it, the pass criteria, the fix and the risk of the fix.
