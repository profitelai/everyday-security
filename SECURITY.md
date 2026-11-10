# Security policy

Everyday Security is an Alpha tool that scans systems. Please report problems in the tool itself responsibly.

## Report a vulnerability in this project
- Use GitHub's **private vulnerability reporting** on this repository ("Security" tab, then "Report a vulnerability"). Please do not open a public issue for a security problem.
- If that is not available to you, use the contact details at https://www.profitell.com/.
- Include: what you found, the version (`VERSION` in `everyday/__init__.py`), steps to reproduce, and the impact you believe it has.
- We will acknowledge a report as soon as we reasonably can and tell you what we plan to do. This is a small project: we cannot promise a fixed response time or a bug bounty.

## What counts
- Code that could harm the machine running the tool or the systems it scans beyond the documented checks.
- The local workbench (`tools/workbench`) accepting requests it should refuse (it should listen on 127.0.0.1 only).
- Path traversal, command injection, or leaking of scan results.

## What does not count
- A wrong finding (false positive or false negative) is a normal bug: open a regular issue with the evidence. The tool is Alpha and its accuracy is not yet measured.
- Disagreement with a check's advice. The checks are drafts from cited public sources.

## Using the tool safely
Only scan systems you own or have written permission to scan. See the Disclaimer in `README.md`.
