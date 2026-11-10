---
id: MAIL-004
title: "DMARC policy is moved from none to quarantine to reject, guided by reports"
pillar: mail-authentication
severity: high
standards: [RFC 7489]
sources: [S-RFC7489, S-GOOGLE-SENDER, S-NIST-SP800-177]
tags: [email, dmarc, enforcement, spoofing, domain]
target: domain
method: dns-lookup
tool: dig
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-004 · DMARC policy is moved from none to quarantine to reject, guided by reports

## Why it matters
Only `quarantine` and `reject` stop spoofed mail from reaching inboxes. A domain stuck at `p=none` for years is monitored but not protected. The safe route is gradual, and it only works if somebody actually reads the aggregate reports to find legitimate senders that are not yet aligned.

## How to test
```bash
dig +short TXT _dmarc.example.com
checkdmarc example.com
```
Then open the last few weeks of aggregate reports (or your report-processing service) and look for sources that send as your domain and fail both SPF and DKIM alignment.

## Pass criteria
The policy is `p=quarantine` or `p=reject`, with `pct` absent or 100 and any `sp=` subdomain policy equal or stricter. The report mailbox is read at least weekly during rollout and monthly afterwards, and every legitimate source in the reports passes with an aligned SPF or DKIM identity.

## Fix
Ramp up in steps: `p=none`, then `p=quarantine; pct=10` rising to 100, then `p=reject`, waiting a couple of weeks between steps while reports are clean. Fix each failing legitimate sender first: add it to SPF or, better, have it sign with DKIM for your domain.

## Risk and rollback
Strict policies bounce or junk legitimate mail that is not aligned, and mailing lists and some forwarders rewrite messages in ways that break alignment. Lower the record TTL before each step. Rollback: set `p=none` again; receivers pick this up once their cached copy expires.
