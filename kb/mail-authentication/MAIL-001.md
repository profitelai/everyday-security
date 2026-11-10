---
id: MAIL-001
title: "SPF is published once, stays within 10 DNS lookups and ends in -all or ~all"
pillar: mail-authentication
severity: high
standards: [RFC 7208]
sources: [S-RFC7208, S-NIST-SP800-177]
tags: [email, spf, dns, spoofing, domain]
target: domain
method: dns-lookup
tool: dig
automated: yes
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-001 · SPF is published once, stays within 10 DNS lookups and ends in -all or ~all

## Why it matters
SPF lets a domain list which servers may send mail for it. Without a record, anyone can pass off mail as your domain with no SPF signal at all. A record that is malformed, duplicated or too expensive to evaluate is worse than it looks: receivers return a permanent error and treat it as if no usable policy existed.

## How to test
```bash
dig +short TXT example.com | grep -i 'v=spf1'
checkdmarc example.com            # reports SPF validity and the DNS lookup count
```
Count by hand if needed: each `include`, `a`, `mx`, `ptr` and `exists` term and each `redirect` modifier is one lookup, including those inside nested includes. `ip4`, `ip6` and `all` cost nothing.

## Pass criteria
Exactly one TXT record starts with `v=spf1`. Evaluation needs no more than 10 lookup-causing terms and no more than two lookups that return nothing. The record ends in `-all` or `~all` (not `+all`, `?all` or missing). The `ptr` mechanism is absent.

## Fix
Merge multiple SPF records into one. Remove includes for services you no longer use. Replace `a`/`mx` terms with literal `ip4`/`ip6` ranges where the addresses are stable. Finish with `-all` once every real sender is listed; `~all` is acceptable while you are still discovering senders or when DMARC enforcement (MAIL-004) carries the weight.

## Risk and rollback
Dropping a legitimate sender (a CRM, invoicing tool or newsletter service) makes its mail fail SPF, and with a strict DMARC policy it may be rejected. Keep a copy of the old record, make the change with a short TTL, and watch bounces and DMARC reports for a week. Rollback: republish the saved record.
