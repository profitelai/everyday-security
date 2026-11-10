---
id: PRIV-010
title: "Access, rectification and portability requests are answered in writing within 30 days"
pillar: privacy-compliance
severity: medium
standards: ["Law 25 (Quebec)", "PIPEDA", "GDPR"]
sources: [S-QC-P391, S-CAI-RESPONSABLE, S-PIPEDA, S-GDPR]
tags: [privacy, law-25, access-requests, portability, process]
target: process
method: manual-review
tool: policy-review
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-010 · Access, rectification and portability requests are answered in writing within 30 days

## Why it matters
In Quebec, a person may ask in writing, addressed to the person in charge and with proof of identity, to see their information, get a copy, or have it corrected (ss. 27, 28, 30). The person in charge must reply in writing, promptly and no later than 30 days after receipt; silence counts as a refusal (s. 32). Access is free, though a reasonable charge for transcription, copying or sending is possible if the person is told the approximate amount first (s. 33). A refusal must give reasons, the legal provision relied on, the remedies and their deadline (s. 34). Information the person supplied that is computerized, and not created or inferred by you, must be given on request in a structured, commonly used format unless that raises serious practical difficulties (s. 27). The public must be told where and how to ask (s. 29). PIPEDA s. 8(3) also says 30 days (with limited extensions in s. 8(4)); GDPR Art. 12(3) says one month, extendable. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. Check the privacy page says where and how to send a request and reaches the person in charge.
2. Send a test access request from a test person's identity. Log the received date and compute day 30.
3. Follow the data: using the inventory, can you find everything about that person, including at providers, backups and email?
4. Check the export is in CSV or JSON, covers only what was collected from the person, and is delivered securely.
5. Read the refusal template for reasons, legal basis, remedies and time limit. Check the rectification path issues a copy of changed data or a confirmation of deletion.

## Pass criteria
A published channel, a request log with received and due dates, a tested search across all stores, an export in a structured format, templates for grant and refusal, and a test answered inside 30 days. Information tied to a refused request is retained until the person's recourses run out (s. 36).

## Fix
Create a request form or mailbox, a one-page procedure, and a tracking sheet with automatic due dates. Prepare a script to export a person's records. Verify identity proportionately without collecting more identification than needed.

## Risk and rollback
Handing data to the wrong person is itself an incident (PRIV-006). Verify identity before release. Collecting a copy of a passport to verify a request over-collects; use less intrusive checks. Rollback: if a response went out incomplete, send a dated supplement and note it in the log.
