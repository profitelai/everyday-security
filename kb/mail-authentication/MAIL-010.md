---
id: MAIL-010
title: "Mailbox accounts use multi-factor authentication and strong, unique passwords"
pillar: mail-authentication
severity: high
standards: [NIST SP 800-63B]
sources: [S-NIST-SP800-63B, S-CISA-MFA]
tags: [mfa, passwords, authentication, mail]
target: process
method: manual-review
tool: nmap
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-010 · Mailbox accounts use multi-factor authentication and strong, unique passwords

## Why it matters
A stolen mailbox lets an attacker send convincing mail as you, reset passwords on other services and read invoices. SPF, DKIM and DMARC do not help once the real account is taken over. A second factor stops most password-only takeovers, and a password that is long and not reused or breached stops the rest.

## How to test
Review the account list in your mail provider's admin console or your mail server's user store, and note which accounts have a second factor enrolled. Then find every way a password alone can still log in:
```bash
nmap -Pn -p 25,110,143,465,587,993,995 mail.example.com
```
Open ports 110, 143, 465, 587, 993 and 995 mean IMAP, POP3 or SMTP logins with a password only, which webmail MFA does not cover.

## Pass criteria
Every mailbox that can log in has MFA enrolled or enforced by policy, administrators and finance staff first, ideally with a phishing-resistant method. Passwords are unique per account, long, not shared between people and checked against lists of known breached or common passwords. Password-only IMAP, POP3 and SMTP access is disabled or limited to per-application passwords.

## Fix
Turn on enforced MFA in the provider's admin settings, or enable a two-factor plugin on self-hosted webmail. Move users to a password manager, block common and breached passwords, and disable unused legacy protocols. Add login rate limiting such as fail2ban on the remaining ones.

## Risk and rollback
Enforcing MFA can lock out people who lose their device, and old mail clients that cannot do modern sign-in stop working. Keep two administrator accounts with saved recovery codes, roll out in groups, and brief staff first. Rollback: an administrator resets a user's enrolment or relaxes the policy for a group.
