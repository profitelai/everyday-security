---
id: PRIV-007
title: "A tested procedure decides when to notify the Commission and affected people, and staff know how to report"
pillar: privacy-compliance
severity: high
standards: ["Law 25 (Quebec)", "PIPEDA", "GDPR"]
sources: [S-QC-P391, S-QC-INCREG, S-CAI-INCIDENTS, S-CAI-SANCTIONS, S-PIPEDA, S-OPC-BREACH, S-GDPR]
tags: [law-25, incident-response, breach-response, training, privacy]
target: process
method: manual-review
tool: policy-review
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-007 · A tested procedure decides when to notify the Commission and affected people, and staff know how to report

## Why it matters
When a confidentiality incident is suspected, the Quebec Act (s. 3.5) requires reasonable steps to reduce the risk of injury and prevent a repeat. If the incident presents a risk of serious injury, the Commission d'acces a l'information and the people concerned must be notified promptly; the Commission can order notice to individuals if you do not. The risk assessment must weigh the sensitivity of the information, the expected consequences of its use and how likely misuse is, and must involve the person in charge (s. 3.7). The regulation sets what each notice must contain (Reg. ss. 3 to 6). Other regimes use different tests: PIPEDA s. 10.1 speaks of a real risk of significant harm; GDPR Art. 33 sets a 72-hour clock to the authority unless risk is unlikely. Failing to report is among the breaches the Commission can penalize. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. Read the written procedure: who decides, who is called first, where the Commission's notice form is kept, templates for notices to individuals.
2. Run a short tabletop exercise with a scenario (customer list emailed to the wrong person, stolen laptop, ransomware on the file server). Time how long it takes to reach a documented decision and draft the Commission notice.
3. Check the draft notice against the regulation's list (the list is longer than this summary; read the regulation itself): business identity and contact, information involved, circumstances, dates, number of people, reasons for the risk conclusion, notification plans, measures taken.
4. Ask two staff, including a non-technical one, whom they tell and how fast.

## Pass criteria
A written procedure names roles, uses the three risk factors, and ties each decision to the register (PRIV-006). Templates exist for the Commission notice and the notice to individuals with the required elements. Public notice is only planned for the circumstances the regulation allows. Staff can state the reporting route. An exercise has been run in the last 12 months.

## Fix
Write a two-page runbook, store it where it is reachable when systems are down, add the Commission's form link, and include providers' emergency contacts. Brief all staff once a year and at onboarding.

## Risk and rollback
Over-notifying causes alarm and cost; under-notifying risks orders and penalties. Record the reasoning either way and consult counsel on borderline cases. Rollback: if a notice was sent in error, send a dated correction rather than silence.
