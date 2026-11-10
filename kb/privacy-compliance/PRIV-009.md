---
id: PRIV-009
title: "Every service provider that handles personal data is bound by a written agreement"
pillar: privacy-compliance
severity: high
standards: ["Law 25 (Quebec)", "PIPEDA", "GDPR"]
sources: [S-QC-P391, S-CAI-COMMUNICATION, S-CAI-CONSERVATION, S-PIPEDA, S-GDPR]
tags: [law-25, processors, privacy]
target: process
method: manual-review
tool: policy-review
automated: no
status: draft
drafted: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-009 · Every service provider that handles personal data is bound by a written agreement

> Informational only, not legal advice. Laws, dates and time limits change; confirm the current text of the cited source or ask a qualified professional before relying on this check.

## Why it matters
Quebec's Act (s. 18.3) lets a business share personal information with a provider without individual consent when it is needed for a mandate or service, but only if the mandate or contract is in writing and states the measures the provider must take to keep the information confidential, to use it only for that job, and not to keep it after the contract ends. The provider must tell the person in charge without delay of any breach or attempted breach and let that person run confidentiality checks. A narrow carve-out exists for public bodies and members of a professional order; ask counsel if it applies. PIPEDA 4.1.3 keeps you responsible for data given to a processor and expects contractual or other means of comparable protection; GDPR Art. 28(3) lists contract terms for processors. The Commission also says you remain responsible for incidents at a third party holding your data. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. From the inventory (PRIV-004) list every provider: hosting, email, CRM, newsletter, payments, analytics, accountant, IT contractor, shredding, call centre, chat.
2. For each, find the signed contract or accepted online terms. Check for: protective measures; use only for your purpose; return or deletion at the end; duty to alert you promptly to violations or attempts; your right to verify.
3. Where standard SaaS terms lack one of these, look for a data-processing addendum you can sign.
4. Check you hold a working incident contact for each provider and a documented offboarding step for ended contracts.

## Pass criteria
Every provider with access has a written agreement that contains the five elements, or an addendum that closes the gap. An incident contact is recorded. Ended contracts have evidence of deletion or return.

## Fix
Keep one contract checklist and attach it to each vendor file. Ask vendors for their DPA; for small local providers use a short addendum. Where a destruction company is used, add the process, confidentiality undertaking and reporting duties the Commission lists.

## Risk and rollback
Pushing on contract terms can delay onboarding or limit tool choice. If a vendor will not agree, restrict the data you send to it or replace it. Rollback: stop sending personal data to that vendor until terms are fixed, and request deletion under the existing terms.
