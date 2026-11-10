---
id: MAIL-005
title: "Domains that never send or receive mail publish a deny-all SPF, a reject DMARC and a null MX"
pillar: mail-authentication
severity: medium
standards: [RFC 7208, RFC 7489, RFC 7505]
sources: [S-RFC7208, S-RFC7489, S-RFC7505, S-RFC6376]
tags: [spf, dmarc, mail, domain]
target: domain
method: dns-lookup
tool: dig
automated: yes
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-005 · Domains that never send or receive mail publish a deny-all SPF, a reject DMARC and a null MX

## Why it matters
Parked, retired and defensive-registration domains are favourite spoofing material because nobody watches them. Publishing three short records tells receivers that no mail from the domain is legitimate. A null MX also tells senders to stop at once, instead of falling back to the domain's address record and retrying a mail server that does not exist.

## How to test
```bash
dig +short TXT parked-example.com | grep -i spf1
dig +short TXT _dmarc.parked-example.com
dig +short MX parked-example.com
dig +short TXT '*._domainkey.parked-example.com'
```
Run it for every domain you own, including common misspellings and old brand names. List them from your registrar account first.

## Pass criteria
SPF is exactly `v=spf1 -all`. DMARC is `v=DMARC1; p=reject;` (an `rua` address is welcome). MX is a single record, preference 0, whose target is `.`. Optionally, a wildcard `*._domainkey` TXT record of `v=DKIM1; p=` marks every selector as revoked.

## Fix
Add the records at the zone apex. DMARC covers subdomains by default, but SPF does not, so a subdomain that resolves in DNS needs its own `v=spf1 -all`.

## Risk and rollback
Only apply this to a domain that truly has no mailboxes and no sending services; check the zone, mail logs and DMARC reports first. If the domain does send or receive, mail is rejected or bounces. Rollback: replace the three records with the previous ones.
