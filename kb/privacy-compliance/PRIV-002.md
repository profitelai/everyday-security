---
id: PRIV-002
title: "A plain-language privacy policy is published and matches what the site really collects"
pillar: privacy-compliance
severity: high
standards: ["Law 25 (Quebec)", "PIPEDA", "GDPR"]
sources: [S-QC-P391, S-CAI-COLLECTE, S-OPC-PRINCIPLES, S-GDPR]
tags: [privacy, law-25, privacy-policy, transparency, website]
target: website
method: manual-review
tool: browser
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-002 · A plain-language privacy policy is published and matches what the site really collects

## Why it matters
A business that collects personal information through technology, a website included, must publish a confidentiality policy in clear, simple language and announce changes to it (Quebec Act, s. 8.2). At collection time people must also be told the purposes, the means of collection, their rights of access and rectification and their right to withdraw consent (s. 8), plus the third parties involved and any possibility of communication outside Quebec. The Commission d'acces a l'information describes a good policy as covering what is collected and why, who receives it, protections, cookie use, rights and remedies, and changes. A policy that does not match reality misleads visitors. For a business with no EU establishment, GDPR can still reach it where it offers goods or services to people in the EU or monitors their behaviour there (Art. 3(2)); whether that applies to you is a question for counsel. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. In a private window, find the policy link on the home page and on every form.
2. List what the site actually collects. Count every form field (contact, quote, newsletter, login, checkout). In browser DevTools (Network tab) note each third-party host; from a shell: `curl -s https://example.com/ | grep -oE '(src|href)="https?://[^"/]+' | sort -u`. In Application > Cookies note what is set.
3. Read the policy beside that list. Each data type, purpose and recipient observed should appear in it, and nothing should be claimed that is not happening.
4. Check it names the contact of the person in charge, mentions cookies if used, says whether data may leave Quebec, and shows a date.

## Pass criteria
The policy is linked from every page and every form, is readable by a non-lawyer, and is consistent with the observed fields, third parties and cookies in both directions. Changes are dated and announced.

## Fix
Rewrite from the inventory of what you collect (see PRIV-004), not from a generic template. Remove claims you cannot back. Add each processor you use and say if storage or support is outside Quebec. Keep earlier versions.

## Risk and rollback
Trimming a policy to match reality may reveal trackers or fields you did not mean to have; remove them rather than hide them. Rollback: restore the previous version from your dated archive, then fix the gap openly.
