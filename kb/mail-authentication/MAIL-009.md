---
id: MAIL-009
title: "Each outgoing mail IP has a reverse DNS name that resolves back to the same IP"
pillar: mail-authentication
severity: medium
standards: [RFC 1912, RFC 5321]
sources: [S-RFC1912, S-RFC5321, S-GOOGLE-SENDER]
tags: [email, reverse-dns, ptr, deliverability, server]
target: mail
method: dns-lookup
tool: dig
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-009 · Each outgoing mail IP has a reverse DNS name that resolves back to the same IP

## Why it matters
Receivers look up the PTR record of the connecting IP and check that the name leads back to the same address (forward-confirmed reverse DNS). A mismatch or missing record is a routine reason for mail to be junked or refused. Gmail's sender guidelines list valid forward and reverse records as a requirement.

## How to test
```bash
dig +short -x 203.0.113.25                 # PTR for the sending IP (use your real address)
dig +short A mail.example.com              # must return 203.0.113.25
dig +short AAAA mail.example.com           # repeat for IPv6 if you send over it
printf 'QUIT\r\n' | nc -w 10 203.0.113.25 25   # the 220 banner shows the server's own name
```

## Pass criteria
Every IP that sends mail has exactly one sensible PTR name, and that name is not a CNAME. Looking that name up returns the original IP. The name in the SMTP greeting and the EHLO the server uses when sending is the same name.

## Fix
The PTR record is controlled by whoever owns the IP block, so request it in your hosting or ISP control panel rather than in your own DNS zone. Then create the matching A or AAAA record and set the mail server's hostname (for Postfix, `myhostname`) to the same name.

## Risk and rollback
Changing the PTR is low risk. Changing the server hostname also changes the EHLO name and may no longer match the TLS certificate, so check MAIL-007 afterwards. Allow for DNS caching. Rollback: set the previous PTR and hostname back.
