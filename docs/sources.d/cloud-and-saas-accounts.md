# Sources: cloud and SaaS accounts (pillar `cloud-and-saas-accounts`)

URLs were fetched on 2026-11-09 and returned HTTP 200 (where a vendor redirects an old address, the final canonical address is the one listed). All are public standards or primary vendor documentation; checks cite them and are written in our own words. Existing ledger IDs (S-CISA-MFA, S-NIST-800-63B, S-NIST80053, S-NIST-800-92, S-OWASP-SECRETS, S-OWASP-A01, S-OWASP-A05, S-OWASP-CS-AUTHZ, S-ICANN-EPP) are re-used from the other ledgers, not redefined here.

| ID | Source | Publisher | URL | Usage note |
|---|---|---|---|---|
| S-CISA-PHISHRES-MFA | Implementing Phishing-Resistant MFA (fact sheet) | CISA | https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf | cite only (US government work) |
| S-CISA-SCUBA | Secure Cloud Business Applications (SCuBA) Project | CISA | https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project | cite only; baselines for Microsoft 365 and Google Workspace |
| S-CSA-CCM | Cloud Controls Matrix | Cloud Security Alliance | https://cloudsecurityalliance.org/research/cloud-controls-matrix | cite only; named for orientation, no controls reproduced |
| S-CIS-CONTROLS-V8 | CIS Critical Security Controls, Version 8 | Center for Internet Security | https://www.cisecurity.org/controls/v8 | cite only; control numbers referenced, text not reproduced |
| S-OWASP-CS-LOGGING | Logging Cheat Sheet | OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html | CC BY-SA 4.0; cite only |
| S-GOOGLE-ADMIN-BP | Security best practices for administrator accounts | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/users/security-best-practices-for-administrator-accounts | cite only |
| S-GOOGLE-SMB-CHECKLIST | Security checklist for small businesses (1-100 users) | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/security/security-checklist-for-small-businesses-1-100-users | cite only |
| S-GOOGLE-2SV | Protect your business with 2-Step Verification | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/security/protect-your-business-with-2-step-verification | cite only |
| S-GOOGLE-APP-ACCESS | Control which third-party and internal apps access Google Workspace data | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/apps/control-which-apps-access-google-workspace-data | cite only |
| S-GOOGLE-ACTIVITY-RULES | Create and manage activity rules | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/security/create-and-manage-activity-rules | cite only |
| S-GOOGLE-LOGIN-ALERTS | About admin alerts for suspicious login activity | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/reports/about-admin-alerts-for-suspicious-login-activity | cite only |
| S-GOOGLE-USER-LOG | User log events | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/reports/user-log-events | cite only |
| S-GOOGLE-DELETE-USER | Delete or remove a user from your organization | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/users/delete-or-remove-a-user-from-your-organization | cite only |
| S-GOOGLE-SUSPEND-USER | Suspend a user temporarily | Google Workspace Admin Help | https://knowledge.workspace.google.com/admin/users/suspend-a-user-temporarily | cite only |
| S-MS-EMERGENCY-ACCESS | Manage emergency access admin accounts | Microsoft Learn (Entra ID) | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access | cite only |
| S-MS-ENTRA-ROLES-BP | Best practices for Microsoft Entra roles | Microsoft Learn (Entra ID) | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices | cite only |
| S-MS-AUTH-STRENGTHS | Overview of Microsoft Entra authentication strength | Microsoft Learn (Entra ID) | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths | cite only |
| S-MS-REVOKE-ACCESS | Revoke user access in an emergency in Microsoft Entra ID | Microsoft Learn (Entra ID) | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | cite only |
| S-MS-USER-CONSENT | Configure how users consent to applications | Microsoft Learn (Entra ID) | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent | cite only |
| S-MS-AUDIT-ENABLE | Turn auditing on or off | Microsoft Learn (Purview) | https://learn.microsoft.com/en-us/purview/audit-log-enable-disable | cite only |
| S-AZURE-RBAC-BP | Best practices for Azure RBAC | Microsoft Learn (Azure) | https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices | cite only |
| S-CF-2FA | Two-factor authentication | Cloudflare Docs | https://developers.cloudflare.com/fundamentals/user-profiles/2fa/ | cite only |
| S-CF-MEMBERS | Manage members (accounts and roles) | Cloudflare Docs | https://developers.cloudflare.com/fundamentals/manage-members/ | cite only |
| S-CF-API-TOKENS | Create API token | Cloudflare Docs | https://developers.cloudflare.com/fundamentals/api/get-started/create-token/ | cite only |
| S-CF-AUDIT-LOGS | Audit logs | Cloudflare Docs | https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/ | cite only |
| S-CF-TRANSFER-OUT | Transfer your domain out from Cloudflare (registrar lock) | Cloudflare Docs | https://developers.cloudflare.com/registrar/account-options/transfer-out-from-cloudflare/ | cite only |
| S-GH-REQUIRE-2FA | Requiring two-factor authentication in your organization | GitHub Docs | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization | cite only |
| S-GH-PAT-POLICY | Setting a personal access token policy for your organization | GitHub Docs | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization | cite only |
| S-GH-SECRET-SCANNING | About secret scanning | GitHub Docs | https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning | cite only |
| S-GH-PUSH-PROTECTION | About push protection | GitHub Docs | https://docs.github.com/en/code-security/concepts/secret-security/push-protection | cite only |
| S-GH-OAUTH-APPS | Reviewing your authorized OAuth apps | GitHub Docs | https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/reviewing-your-authorized-oauth-apps | cite only |
| S-GH-AUDIT-LOG | Reviewing the audit log for your organization | GitHub Docs | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization | cite only |
| S-AWS-IAM-BP | Security best practices in IAM | Amazon Web Services | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html | cite only |
| S-AWS-CRED-REPORT | Get credential reports for your AWS account | Amazon Web Services | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html | cite only |
| S-AWS-S3-BPA | Blocking public access to your Amazon S3 storage | Amazon Web Services | https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html | cite only |
| S-GCP-IAM-SECURELY | Use IAM securely | Google Cloud | https://docs.cloud.google.com/iam/docs/using-iam-securely | cite only |
| S-GCP-SA-KEYS | Best practices for managing service account keys | Google Cloud | https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys | cite only |
| S-GCP-PAP | Public access prevention (Cloud Storage) | Google Cloud | https://docs.cloud.google.com/storage/docs/public-access-prevention | cite only |
| S-STRIPE-KEYS-BP | Best practices for managing secret API keys | Stripe Docs | https://docs.stripe.com/keys-best-practices | cite only; example of a payment provider |
