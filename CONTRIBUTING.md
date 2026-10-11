# Contributing to VLUN

## Which layer is current?

There is no single "current" layer; each one is frozen and additive:

| Layer | Source dirs | Status |
|---|---|---|
| v1 | `jsonl/`, `derived/`, `splits_v2/`, `experiments/` | frozen, never rewritten |
| v2.2 | `jsonl_ml/`, `derived_v2_2/`, `splits_v2_2/`, `experiments_v2_2/` | frozen (`jsonl_ml/` is the v2.2 source layer despite the name) |
| v3.0 / v3.1 / v3.2 | `jsonl_v3/`, `derived_v3/`, `splits_v3/`, `experiments_v3/` | frozen; 3.1/3.2 share `derived_v3/` |
| Vbeta | `Vbeta/` (own scripts, splits, benchmarks, gates) | isolated; never touches the rest |

`V3/` (uppercase) is research notes plus git-ignored clones — not the v3
dataset, which lives in the lowercase `jsonl_v3/` / `derived_v3/` dirs.
The pre-quarantine `splits/` directory was retired; the shipped splits are
`splits_v2/`. `work/`, `V3/clones/`, `nextdata/` are git-ignored inputs.

For ML use, start with `benchmark/` (families A–V) and `training/`;
for provenance questions, start with `reports/` and `docs/DATASHEET.md`.

## Rules that fail the build if broken

- `jsonl/`, `jsonl_ml/`, `jsonl_v3/` are **read-only**. Only their
  documented owner scripts may write to them (enforced by
  `scripts/check_reproducibility.py`).
- Every derived field carries `{value, evidence_type, source_refs}` from the
  closed vocabulary in `scripts/schema_terms.py` (the single source of
  truth; it fails at import time if a copy drifts). `unknown` is a counted
  outcome — never fill it by guessing.
- No PoC above L1 without a run artefact; no `verified_patch` without the
  vulnerable-vs-fixed comparison.

## Generated files

`README.md`, `NOTICE.md` and `docs/DATASHEET.md` are generated — edit the
generator (`scripts/generate_readme.py`, `scripts/build_datasheet.py`),
never the output. Verify with:

```bash
python scripts/generate_readme.py --check
python scripts/build_datasheet.py --check
python scripts/run_gates.py          # all 21 gates; skips stay skipped_no_network
python -m unittest discover -s tests # 175 tests
```

`Vbeta/present_snapshot.json` pins `README.md` and other PRESENT files.
If you change one deliberately, re-snapshot with a reason:

```bash
python Vbeta/scripts/validate_vbeta.py --resnapshot "<why>"
```
