# Provenance

Every part of this repository, where it came from, and what is still open.

| Part | Origin | Status |
|---|---|---|
| `tools/workbench/` | Written by Profitell Security Consulting in November 2026. | Ours. |
| `tools/scanner/security_review.py` | Written by Profitell Security Consulting for its own server reviews. | Ours. Its check list was first drafted while a third-party checklist was open for reference, so before 1.0 each check gets an independent written specification from public standards (OWASP, IETF RFCs, vendor documentation) and a review. |
| `LICENSE` | Standard unmodified Apache License 2.0 text; only the appendix copyright line is ours. | Standard text. |
| `kb/` (13 pillars) | Written for this repository in November 2026 from public standards and primary documentation (IETF RFCs, W3C/WHATWG specifications, vendor and distribution documentation, Quebec and Canadian statutes and regulator guidance, OWASP Top 10 as a category list). Drafted by independent writing passes that were barred from opening any third-party knowledge base. Every check cites its sources in `docs/sources.md` and `docs/sources.d/`. | Ours. Overlap with the previously used third-party security brain: highest check 2.4% of 6-word sequences, none above 10%; against the whole 11,274-file third-party skills folder none above 10%. This is evidence for review, not a legal finding. |
| Everything else | Written for this repository. | Ours. |

## What this repository does not contain

No file, text, structure, script, preset or note from any third-party knowledge base or "brain" product has been copied, modified or renamed into this repository. Material that is derived from third-party work stays outside it, with its original notices, until it has been replaced by independently written content.

## Rules for adding content

1. Written from public standards and primary documentation, with the source recorded in `docs/sources.md`.
2. Never copied from, and never lightly reworded from, another project's text.
3. Third-party notices are never removed from third-party files.
4. Similarity is checked against the sources consulted before release; a similarity score is evidence for human review, not a legal determination.

## Independence gates (run before every release)

```bash
python3 tools/kb/lint.py
python3 tools/kb/similarity.py PATH_TO_ANY_THIRD_PARTY_FOLDER --max 0.10
```

A qualified lawyer should review the repository before it is made public.
