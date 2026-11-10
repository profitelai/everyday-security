---
id: PRIV-001
title: "A named person is accountable for personal information and the contact and governance practices are published"
pillar: privacy-compliance
severity: high
standards: ["Law 25 (Quebec)", "PIPEDA"]
sources: [S-QC-P391, S-CAI-RESPONSABLE, S-OPC-PRINCIPLES, S-PIPEDA]
tags: [privacy, law-25, accountability, governance, website]
target: website
method: manual-review
tool: browser
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-001 · A named person is accountable for personal information and the contact and governance practices are published

## Why it matters
Under the Quebec private-sector Act (s. 3.1), the highest authority in the business is by default the person in charge of protecting personal information, may delegate the role in writing, and the title and contact details must be published on the website (or by another appropriate means if there is no site). Section 3.2 adds governance policies and practices: they must frame how information is kept and destroyed, define staff roles across its life cycle and provide a complaints process, be approved by that person, and be published in simple, clear language. PIPEDA's first principle asks for the same thing in federal terms: someone designated and accountable. If nobody can be found, access requests, complaints and incident reports have nowhere to land. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. Open the site in a private window. From the footer or privacy page, find the title and contact details of the person in charge.
2. Send a test message to that contact from an outside address. Record when a human replies.
3. Ask for the written delegation if the person named is not the head of the business.
4. Find the published governance page. Tick off: keeping and destruction rules, staff roles and responsibilities, how to make a complaint, and a statement that the person in charge approved it.

## Pass criteria
A title and a monitored contact (a role mailbox such as privacy@ is better than a personal address) are published. A written delegation exists when needed. The governance page is in plain language, covers the three required elements, matches what the business really does, and carries a date.

## Fix
Name the person, write a one-page delegation signed by the head of the business, create a role mailbox that survives staff changes, and publish a short governance page. Draft it from your real practices, not from a template you do not follow.

## Risk and rollback
Publishing a personal mailbox invites spam and breaks when the person leaves. Over-promising on the governance page is worse than a short honest one, because it misstates your practice. Rollback: edit or withdraw the page and keep dated versions so earlier statements can be explained.
