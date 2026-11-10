---
id: MAIL-007
title: "Every MX host offers STARTTLS with a valid certificate and TLS 1.2 or newer"
pillar: mail-authentication
severity: medium
standards: [RFC 3207, RFC 8461]
sources: [S-RFC3207, S-RFC8461, S-NIST-SP800-177]
tags: [certificates, mail, tls]
target: mail
method: tls-handshake
tool: openssl
automated: yes
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-007 · Every MX host offers STARTTLS with a valid certificate and TLS 1.2 or newer

## Why it matters
STARTTLS is how incoming mail gets encryption on port 25. If it is missing, mail between servers crosses the network readable by anyone on the path. If the certificate is expired or names the wrong host, senders that check it (any sender honouring MTA-STS, MAIL-006) will refuse to deliver.

## How to test
Run from a network that allows outbound port 25; many cloud and home networks block it.
```bash
dig +short MX example.com
openssl s_client -starttls smtp -connect mx1.example.com:25 -servername mx1.example.com \
  -verify_hostname mx1.example.com -brief </dev/null 2>&1 | grep -Ei 'protocol|verif'
openssl s_client -starttls smtp -connect mx1.example.com:25 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
```
Repeat for each MX host.

## Pass criteria
The server advertises STARTTLS and the handshake completes with TLS 1.2 or 1.3 (see TLS-001 for the same version rule on websites). Verification reports OK, the certificate has not expired, and its name matches the MX hostname, not just the domain.

## Fix
Install a publicly trusted certificate for the MX hostname and enable it in the mail server, for example Postfix `smtpd_tls_security_level = may` together with the certificate and key parameters. Make the renewal job reload the mail service so the new certificate is actually served. Keep TLS optional (`may`) on public port 25 unless every sender you accept mail from supports it.

## Risk and rollback
Forcing TLS on port 25 for all senders rejects mail from older servers that cannot negotiate it, and raising the minimum protocol does the same for the oldest ones. Check the mail log for the TLS versions in use first. Rollback: restore the previous mail server configuration and reload.
