---
id: PRIV-005
title: "A retention and destruction schedule exists and is actually carried out"
pillar: privacy-compliance
severity: medium
standards: ["Law 25 (Quebec)", "PIPEDA"]
sources: [S-QC-P391, S-CAI-CONSERVATION, S-PIPEDA]
tags: [privacy, law-25, retention, destruction, backups]
target: process
method: manual-review
tool: spreadsheet
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-005 · A retention and destruction schedule exists and is actually carried out

## Why it matters
Once the purposes for which personal information was collected or used are achieved, the Quebec Act (s. 23) requires the business to destroy it or anonymize it, subject to any keeping period set by another law. Governance policies must include a framework for keeping and destroying information (s. 3.2). Information used to make a decision about a person must be kept at least one year after the decision (s. 11). The Commission recommends a written retention calendar that respects legal minimums and a destruction method suited to the medium. PIPEDA Schedule 1 (4.5.2, 4.5.3) likewise expects retention guidelines and procedures for destruction. Old data nobody needs is pure liability in an incident. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. Open the schedule. For each data set in the inventory (PRIV-004) it should show a period, the trigger that starts the clock, and the destruction method.
2. Sample reality: find the oldest record in each store (for example `SELECT MIN(created_at) FROM contacts;`, the oldest message in a mailbox, the oldest backup set) and compare it to the schedule.
3. Ask for the destruction log: date, what was destroyed, method, who did it.
4. Delete one test record and follow it: database, search index, exports, email-marketing tool, and the backup rotation that will eventually drop it.
5. For paper and old devices, check how disks and printers are wiped or destroyed, and whether a provider does it under a written contract.

## Pass criteria
Every data set has a period, trigger and method. Nothing sampled is older than its period unless a legal hold is recorded. A destruction log shows the job ran recently. Backups age out on a known cycle. Anonymization, if used, follows a documented method and not simply a removed name.

## Fix
Write the schedule, automate deletion where the system allows, and add a calendar reminder for manual stores. Identify retention periods set by other laws (tax, employment, sector rules) with your accountant or lawyer rather than guessing. Prefer destruction over anonymization; re-identification is hard to rule out.

## Risk and rollback
Deleting too early can destroy records you must keep or need for a dispute. Take a restricted, time-limited archive before the first large purge and let a second person confirm the scope. Rollback: restore from that archive, then correct the rule.
