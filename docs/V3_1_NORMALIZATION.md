# VLUN V3.1 normalization

V3.0 is intentionally an evidence-ingestion layer. V3.1 adds a separate
normalization pass so report parsing can improve field coverage without
rewriting the immutable source layer or silently promoting report claims.

## Run

From the repository root, after the V3 clones have been populated:

```bash
python scripts/normalize_v3.py --check
python scripts/normalize_v3.py
```

Outputs:

- `derived_v3/normalization_overlay.jsonl` — one row per candidate; only
  evidence-backed upgrades are proposed.
- `derived_v3/normalization_fragments.jsonl` — metadata-only finding
  fragments extracted from Markdown/PDF text.
- `derived_v3/normalized_records_preview.jsonl` — what the existing admitted
  records would look like after safe upgrades.
- `reports/v3/normalization_report.json` and `.md` — coverage and blocked
  extraction diagnostics.

The preview is intentionally separate from `derived_v3/records.jsonl`.
Review the overlay before promoting changes into the canonical records.

## Evidence rules

Normalization may upgrade currently-unknown:

- severity;
- top-level vulnerability class;
- language;
- ecosystem;
- affected file/function/line range;
- published-PoC availability.

It may **not**:

- infer vulnerable or fixed commits;
- infer patch effectiveness;
- assign L2-L6;
- convert a report claim into an experimentally verified fact;
- treat an ambiguous classifier result as a class;
- copy third-party report prose into the dataset;
- automatically admit extracted report fragments as findings.

PDF extraction requires `pdftotext`. If it is absent or a PDF fails to
extract, the record is marked blocked/failed rather than guessed.

## Recommended admission path

1. Run the normalization scan.
2. Inspect class/field coverage by source.
3. Review high-confidence fragments against the source report.
4. Admit only fragments with an unambiguous finding identity and provenance.
5. Rebuild `derived_v3` deterministically.
6. Run the V3 validation gate.
7. Only then queue selected records for PoC reproduction and patch
   verification.

Normalization is therefore **V3.1 evidence enrichment**, not verification.
