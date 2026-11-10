---
id: PRIV-003
title: "Tracking and profiling tools stay off until the visitor chooses, and consent can be withdrawn"
pillar: privacy-compliance
severity: high
standards: ["Law 25 (Quebec)", "PIPEDA", "GDPR"]
sources: [S-QC-P391, S-CAI-COLLECTE, S-CAI-CONSENT, S-GDPR]
tags: [law-25, cookies, consent, privacy, web]
target: website
method: manual-review
tool: browser
automated: no
status: draft
reviewed: 2026-11-09
author: Profitell Security Consulting
---

# PRIV-003 · Tracking and profiling tools stay off until the visitor chooses, and consent can be withdrawn

## Why it matters
Quebec's Act (s. 8.1) says that when you collect information using technology that can identify, locate or profile a person, you must first tell them about it and about the means available to activate those functions. Profiling means using personal information to assess traits such as interests or behaviour. The Act does not use the words "off by default" itself; the Commission reads the rule as meaning these functions cannot be switched on by default, the person must turn them on voluntarily. Section 9.1 (highest-confidentiality defaults for privacy settings) expressly leaves browser-cookie settings out, so do not rely on it for cookies. Consent must be clear, free, informed and tied to specific purposes (s. 14), and people may withdraw consent (s. 8). GDPR Art. 7(3) adds that withdrawing must be as easy as giving consent. This is operational guidance, not legal advice; confirm obligations for your situation with a qualified lawyer.

## How to test
1. Open a fresh private window with no stored choice. Open DevTools (Network and Application tabs) before the page loads. Do not click the banner.
2. Record requests to analytics, advertising, session-replay, social and chat hosts, and every cookie or local-storage identifier that is set.
3. Click the refuse option, reload, repeat the capture. Then accept, reload, and use the control that withdraws consent (usually a footer link). Reload again and confirm the tools stop and identifiers are cleared.
4. Check that choices are per purpose, nothing is pre-ticked, and refusing is no harder than accepting.

## Pass criteria
Before a choice, only strictly necessary technology runs; no profiling, advertising or analytics identifiers are set. Refusal works. Withdrawal is reachable from every page, takes effect on the next load, and a record of the visitor's choice (date, purposes) is kept.

## Fix
Load tags only after consent through your tag manager's consent controls, or remove the tools you do not need. Prefer aggregate, cookieless analytics where it meets your goal. Separate purposes (statistics, advertising) into separate toggles.

## Risk and rollback
Blocking tags before consent reduces reported traffic and ad attribution; that is expected. A banner that shows but does not actually stop tags is worse than none because it is untrue. Rollback: re-enable a single tag in the tag manager, but only behind the consent gate.
