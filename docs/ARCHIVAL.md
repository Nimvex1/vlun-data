# Archival — minting the citable DOI (Zenodo)

For research use a dataset needs a citable artifact. GitHub alone is not
one; a Zenodo DOI is. Everything needed to mint it is prepared in-repo —
minting itself needs one authenticated action (no push required until you
ask for it).

## Prepared

- [`CITATION.cff`](../CITATION.cff): credits the dataset compiler
  (`Nimvex1`) alongside the original finding authors (Code4rena
  participants, audit firms, contest platforms). Findings, verdicts and PoC
  code belong to their original authors (see [`NOTICE.md`](../NOTICE.md));
  compilation, normalization, harnesses and benchmarks are the compiler's.
- [`.zenodo.json`](../.zenodo.json): Zenodo deposition metadata (title,
  creators, license `cc-by-4.0`, keywords, GitHub relation). The GitHub–
  Zenodo integration reads this file on release.

## Mint (one action, when you are ready)

1. Enable the GitHub–Zenodo integration for `Nimvex1/vlun-data`
   (zenodo.org → GitHub → flip the switch).
2. Create a GitHub Release for the version in `CITATION.cff`
   (`version: 2.2`). Zenodo archives the release snapshot and mints the DOI.
3. Copy the DOI back into `CITATION.cff`:
   `doi: 10.5281/zenodo.<id>` at top level and under `preferred-citation`.
4. Regenerate: `python scripts/generate_readme.py` (README/NOTICE are
   generated and carry the version), then run the gates.

## What is NOT done yet (honestly)

No DOI exists in this snapshot — one cannot be minted offline, and nothing
is pushed until asked. Any `doi:` value appearing before step 2 completes
would be fabricated. The metadata above is the complete preparation; steps
1–4 are the remaining ~15 minutes.
