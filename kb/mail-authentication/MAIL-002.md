---
id: MAIL-002
title: "Outgoing mail is DKIM-signed with a 2048-bit key published in DNS"
pillar: mail-authentication
severity: high
standards: [RFC 6376, RFC 8301]
sources: [S-RFC6376, S-RFC8301, S-NIST-SP800-177]
tags: [dkim, encryption, mail, dns, domain]
target: domain
method: dns-lookup
tool: dig
automated: yes
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-002 · Outgoing mail is DKIM-signed with a 2048-bit key published in DNS

## Why it matters
A DKIM signature proves that a message was approved by the signing domain and was not altered in transit. It also survives forwarding, which SPF does not, so it is usually what keeps DMARC passing for legitimate mail. Short RSA keys can be broken offline; the DKIM update standard sets 1024 bits as the floor and recommends 2048.

## How to test
DKIM keys live under a selector you cannot guess from outside. Send a message to a mailbox you control, open its raw headers and read `d=` and `s=` in the `DKIM-Signature` line. Then, for selector `s1`:
```bash
dig +short TXT s1._domainkey.example.com
dig +short TXT s1._domainkey.example.com | tr -d '" ' | tr ';' '\n' | grep '^p=' | cut -c3- \
  | base64 -d | openssl rsa -pubin -inform DER -noout -text | head -1
```
The second command prints the key size, for example `Public-Key: (2048 bit)`.

## Pass criteria
Every system that sends as the domain (mail server, marketing tool, helpdesk, invoicing app) signs with its own selector. Each selector publishes a non-empty `p=` key of at least 2048 bits. Signatures in real messages show `dkim=pass` in the receiving `Authentication-Results` header.

## Fix
Generate a 2048-bit RSA key pair in the signer (OpenDKIM, your mail provider or the sending service) and publish the public part as a TXT record. A 2048-bit key exceeds 255 bytes, so the record is stored as several quoted strings; most DNS panels split it for you. Rotate by adding a new selector, switching the signer to it, and removing the old selector after a few days.

## Risk and rollback
A wrongly copied key (stray spaces, a missing chunk) makes every signature fail, so test with a message to an outside mailbox before switching the signer. Keep the old selector published until queued mail has been delivered. Rollback: point the signer back at the previous selector.
