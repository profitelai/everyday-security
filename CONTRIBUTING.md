# Contributing

Thank you for helping. This project is Alpha and values correct, cited, honest content over volume.

## Ground rules
1. **Write in your own words from public sources.** Every check cites public standards or primary documentation in `docs/sources.md` or `docs/sources.d/`. Do not paste text, structure or code from another security knowledge base, scanner or book. If you are unsure whether you may use something, leave it out and say so in the pull request.
2. **Cite everything you claim.** A new check needs real source IDs, 2 to 5 tags from `data/tags.json`, the fixed sections, and `status: draft`.
3. **Do not claim review that has not happened.** Only a named human reviewer may be recorded in a check, and only with their agreement.
4. **No private data.** No real hostnames, IP addresses, keys, tokens or scan reports of systems that are not yours.
5. **Only test systems you own or may test.**

## Before you open a pull request
```bash
python3 -m unittest discover -s tests
python3 tools/kb/lint.py
./everyday.sh validate
python3 tools/kb/build_index.py      # regenerates kb/INDEX.md and the README counts
python3 tools/kb/build_coverage.py   # regenerates docs/coverage/ (the "what we scan" pages)
```
All five must pass. Add a test for new behaviour. A confirmed false positive or false negative should arrive with a regression test.

## Adding scan data
Use the pending-then-approve route (`./everyday.sh ingest ...`, see `docs/DATA-FORMAT.md`) so every rule carries a source and a licence.

## Licence of contributions
By contributing you agree that your contribution is provided under the repository's licence (see `LICENSE`), and that you wrote it or have the right to submit it.
