---
id: MAIL-008
title: "The mail server is not an open relay"
pillar: mail-authentication
severity: critical
standards: [RFC 5321]
sources: [S-RFC5321, S-NIST-SP800-177]
tags: [email, open-relay, smtp, abuse, server]
target: mail
method: server-config
tool: swaks
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-008 · The mail server is not an open relay

## Why it matters
An open relay accepts mail from anyone for delivery to anyone. Spammers find these within hours, send through them under your IP address, and get it blocklisted, which then breaks your own legitimate mail. The base mail standard lets a server refuse relaying for policy reasons, and expects it to use that freedom.

## How to test
Run from a machine outside your network, with two mailboxes you control at unrelated external domains. Stopping after RCPT means no message is ever sent.
```bash
swaks --server mail.example.com --port 25 \
  --from tester@your-other-domain.example --to you@a-third-domain.example --quit-after RCPT
swaks --server mail.example.com --port 587 --tls \
  --from tester@your-other-domain.example --to you@a-third-domain.example --quit-after RCPT
```
Repeat from a host inside any network range the server trusts, and from a container or proxy that fronts the server, because those often make every client look local.

## Pass criteria
Both RCPT commands are refused with a 5xx reply (for example a "relay access denied" message) when the client has not authenticated and neither address is hosted on the server. Delivery to your own domain's mailboxes still works. Port 587 only relays after successful authentication.

## Fix
Postfix: `smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination`, and keep `mynetworks` limited to loopback and specific internal addresses, never a broad range such as a whole container or cloud network. Other servers have an equivalent: relay only for authenticated users or listed hosts. Reload and re-run both tests.

## Risk and rollback
Printers, scanners and old applications that send by IP without logging in stop working once relaying is restricted. List their addresses narrowly in `mynetworks` or give them credentials on port 587. Rollback: restore the previous configuration file and reload; do this only briefly, since the open state is itself the incident.
