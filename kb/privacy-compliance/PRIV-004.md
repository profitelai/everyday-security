---
id: PRIV-004
title: "An inventory records what personal data is held, why, where and who can reach it, and forms and logs stay minimal"
pillar: privacy-compliance
severity: medium
standards: ["Law 25 (Quebec)", "PIPEDA", "GDPR"]
sources: [S-QC-P391, S-CAI-COLLECTE, S-CAI-CONSERVATION, S-PIPEDA, S-GDPR]
tags: [law-25, logging, privacy]
target: process
method: manual-review
tool: spreadsheet
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-004 · An inventory records what personal data is held, why, where and who can reach it, and forms and logs stay minimal

## Why it matters
The Quebec Act requires purposes to be set before collecting (s. 4) and collection to be limited to what is necessary for them (s. 5); the Commission adds that in case of doubt a piece of information is treated as not necessary, and recommends listing the types of documents that hold personal information. Security measures must fit the sensitivity, quantity and medium (s. 10), and staff access only what their duties need (s. 20). PIPEDA asks for documented purposes (4.2.1) and no indiscriminate collection (4.4.1). GDPR Art. 30 requires a record of processing for businesses it covers. You cannot meet any of this for data you do not know you hold. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. Build a spreadsheet, one row per data set: contact-form entries, newsletter list, CRM, customer accounts, HR files, support inbox, analytics, access logs, backups. Columns: data elements, purpose, source, system and location (province or country), who has access, provider, retention, sensitivity.
2. Walk every web form. For each field write the purpose; if you cannot, the field is a candidate for removal or for marking optional.
3. Look inside logs for data that should not be there: `grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+' /var/log/nginx/access.log | head` and search for tokens or passwords in query strings.

## Pass criteria
A dated inventory with a named owner covers every store including backups and third-party tools. Each row has purpose, location and retention. Every form field has a recorded purpose and optional fields are marked. Logs hold no form bodies, credentials or email addresses beyond what the purpose requires.

## Fix
Fill the inventory with the people who use each system. Remove unneeded fields, stop logging request bodies and query strings that carry identifiers, and restrict access to the rows that need it. Review when you add a tool and at least yearly.

## Risk and rollback
Removing a field can break a downstream workflow (a CRM import expecting phone numbers); check dependants first. Over-collecting is the larger risk, since every extra field is more to protect, report and destroy. Rollback: restore the field but mark it optional and document the purpose.
