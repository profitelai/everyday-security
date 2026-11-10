---
id: MAIL-003
title: "A single DMARC record exists with a valid policy and an aggregate-report address"
pillar: mail-authentication
severity: high
standards: [RFC 7489]
sources: [S-RFC7489, S-GOOGLE-SENDER, S-NIST-SP800-177]
tags: [email, dmarc, dns, reporting, domain]
target: domain
method: dns-lookup
tool: dig
automated: yes
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-003 · A single DMARC record exists with a valid policy and an aggregate-report address

## Why it matters
DMARC tells receivers what to do when mail claiming your domain fails SPF and DKIM alignment, and it asks them to send you daily reports of who is using your domain. Without it, receivers apply their own guesses, and you are blind to both abuse and your own misconfigured senders. Gmail's sender guidelines also ask bulk senders for a DMARC record, and accept a policy of none to satisfy that.

## How to test
```bash
dig +short TXT _dmarc.example.com
dig +short TXT example.com._report._dmarc.reports-provider.example   # only if rua points to another domain
```
The second query applies when the `rua` mailbox is in a different domain than the one being protected.

## Pass criteria
Exactly one TXT record at `_dmarc` begins with `v=DMARC1`. It contains `p=` set to `none`, `quarantine` or `reject`, and `rua=mailto:` with an address that exists and is monitored. If that address belongs to another domain, that domain publishes the authorizing `v=DMARC1` record shown above. A policy of `none` passes this check; moving beyond it is MAIL-004.

## Fix
Publish a monitoring record first, for example `v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com`. Use a dedicated mailbox or a report-processing service for `rua`, because reports can arrive in large numbers and as compressed XML.

## Risk and rollback
`p=none` does not affect delivery, so the main risk is the report mailbox filling up or a typo that invalidates the record (receivers then ignore it). Rollback: delete the TXT record.
