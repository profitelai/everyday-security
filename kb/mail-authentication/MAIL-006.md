---
id: MAIL-006
title: "MTA-STS is enforced and TLS-RPT reporting is enabled for incoming mail"
pillar: mail-authentication
severity: medium
standards: [RFC 8461, RFC 8460]
sources: [S-RFC8461, S-RFC8460, S-NIST-SP800-177]
tags: [mta-sts, mail, tls]
target: domain
method: dns-lookup
tool: dig
automated: yes
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# MAIL-006 · MTA-STS is enforced and TLS-RPT reporting is enabled for incoming mail

## Why it matters
Server-to-server mail normally starts in clear text and upgrades to TLS only if both sides agree, so an attacker on the path can strip the upgrade or present a fake server. MTA-STS lets a domain declare that senders must use TLS and a certificate valid for one of its listed MX hosts. TLS-RPT sends you reports when that fails, so you notice breakage.

## How to test
```bash
dig +short TXT _mta-sts.example.com
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt
dig +short TXT _smtp._tls.example.com
```

## Pass criteria
The `_mta-sts` TXT record starts `v=STSv1;` and carries an `id`. The policy file loads over HTTPS with a valid certificate and shows `version: STSv1`, `mode: enforce`, one `mx:` line per real MX host, and a `max_age` of at least a week. The `_smtp._tls` record reads `v=TLSRPTv1; rua=` followed by a `mailto:` or `https:` address. `mode: testing` is an acceptable temporary stage.

## Fix
Start with `mode: testing` plus TLS-RPT, read the reports for a few weeks, then switch to `enforce`, change the `id` in the TXT record and raise `max_age`. Serve the policy from `mta-sts.example.com` and keep its certificate renewing.

## Risk and rollback
In enforce mode, a wrong `mx:` pattern, an expired MX certificate or a lapsed policy-host certificate makes supporting senders hold or refuse your mail. Do not simply delete the record to back out, because senders keep the cached policy until `max_age` runs out. Rollback: publish `mode: none` and a new `id`, and leave it in place until the old `max_age` has passed.
