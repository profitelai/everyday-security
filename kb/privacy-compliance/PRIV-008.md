---
id: PRIV-008
title: "A privacy impact assessment is done before new systems and before personal data goes outside Quebec"
pillar: privacy-compliance
severity: high
standards: ["Law 25 (Quebec)"]
sources: [S-QC-P391, S-CAI-RESPONSABLE, S-CAI-COMMUNICATION]
tags: [law-25, privacy, cloud]
target: process
method: manual-review
tool: spreadsheet
automated: no
status: draft
drafted: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-008 · A privacy impact assessment is done before new systems and before personal data goes outside Quebec

> Informational only, not legal advice. Laws, dates and time limits change; confirm the current text of the cited source or ask a qualified professional before relying on this check.

## Why it matters
Two triggers in the Quebec Act require a privacy impact assessment. Section 3.3: any project to acquire, develop or overhaul an information system or electronic service delivery system that involves collecting, using, communicating, keeping or destroying personal information. The person in charge must be consulted from the start, the depth must be proportionate to sensitivity, purposes, volume, distribution and medium, and the system must be able to hand a person their computerized data in a structured, commonly used format. Section 17: before communicating personal information outside Quebec (or entrusting someone outside Quebec to collect, use or keep it for you) you assess sensitivity, purposes, the protections including contractual ones, and the legal framework of the destination; the transfer may go ahead only if the assessment shows adequate protection, and a written agreement must reflect the results. The Commission's guidance treats other provinces as "outside Quebec" too, so a cloud region in Ontario counts. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. List every SaaS tool, host, email and analytics provider, and find where each stores or processes your data (provider documentation, region setting in the admin console, contract).
2. Mark every flow that leaves Quebec, including CDNs, support desks and sub-processors you can identify.
3. For each marked flow, ask for the assessment. Check it is dated before the first transfer, covers the four considerations, states a conclusion and any mitigations, and links to the written agreement.
4. For systems added or rebuilt in the last 12 months, check an assessment exists and that the person in charge was consulted at the start.
5. Confirm the privacy policy (PRIV-002) mentions the possibility of communication outside Quebec.

## Pass criteria
A list of outside-Quebec flows exists. Each has a dated assessment with a conclusion and a written agreement. New or rebuilt systems have a proportionate assessment with the person in charge consulted early. Short assessments for low-risk tools are acceptable.

## Fix
Use a one-page template: purpose, data, sensitivity, destination and its legal framework, safeguards, decision, sign-off. For tools you cannot justify, choose a Quebec or Canadian region, or stop sending the data.

## Risk and rollback
Skipping the assessment means you may already be exporting data without a record of why it was safe. If a flow was never assessed, do the assessment now, document the gap, and decide whether to pause the flow until it is done. Rollback of a transfer: switch to a different region or provider and delete from the old one under the contract.
