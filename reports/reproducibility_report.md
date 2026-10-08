# Reproducibility / validation report (point-in-time audit record)

Date: 2026-10-07. Scope: reproducibility, terminology consistency,
automated cross-manifest/count integrity. No finding, severity, taxonomy,
evidence level, patch state or record body was changed by this work.

Regenerate the evidence with (all read-only except where noted):

```bash
python scripts/check_manifests.py          # 119 count/reference checks
python scripts/check_reproducibility.py    # 16 provenance/determinism checks
python -m unittest discover -s tests       # 44 tests (incl. broken fixtures)
python scripts/validate.py                 # 71/71 (authorship gate)
python scripts/validate_v3.py              # 33/33
python scripts/validate_v31.py             # 32/32
python Vbeta/scripts/validate_vbeta.py     # 0 critical failures
python Vbeta/tests/test_vbeta.py           # 26/26
python scripts/generate_stats.py --check   # current
python scripts/generate_readme.py --check  # current
```

## New infrastructure (additive only)

- `scripts/schema_terms.py` — canonical vocabulary; imports (never
  redefines) `vlun.EVIDENCE_TYPES`, `vlun.BENCHMARK_FAMILIES`,
  `poc_classification.POC_LEVELS`, `taxonomy.TOP_LEVEL`,
  `vlun_v3` decisions/levels; adds patch-state roles, count domains,
  layers, deprecated-term rejection. Test asserts Vbeta copies match it.
- `scripts/check_manifests.py` — 101 checks recomputed from canonical
  records (see population rules in its docstring).
- `scripts/check_reproducibility.py` — 13 checks incl. Vbeta rebuild parity
  (artefacts byte-identical across rebuilds) and byte-stability of dumps.
- `tests/` — 39 stdlib tests with intentionally-broken fixtures
  (bad decisions/levels/terms, split overlap+gap, dangling tasks,
  research leaks, false verified_patch).

## Population rules proven (input → output per transition)

- v1 splits_v2 = all 953 jsonl/ rows EXCEPT 8 multi-repo error rows
  (`source.repository == "multiple"`), with 2 cross-split duplicates moved
  to `quarantine/` (alchemix L-05/L-06).
- v1 benchmark A-E = 722 finding ids minus 2 quarantined = 720 tasks;
  F = 458 negatives; G = 38 patches; H/I/J ground in `experiments/` legs.
- v2.2 families K,L,N,O,P,Q = 137 derived_v2_2 ids; M = 37 executed runs.
- splits_v2_2 = 1082 pointers: 945 v1 (resolved by file+sha256) + 137 v2.2
  (resolved by record id). 30 `id:"?"` pointers resolve by content hash, not
  id (documented limitation). v2.2 pointer hashes are stale vs current file
  bytes (warned, cause unknown — not guessed).
- v3: 7712 ledger → 5467 admitted records; splits cover exactly; R = 5467
  tasks; S/T are admitted subsets; T (589) resolves to v3.1 preview rows,
  not derived_v3 records (fragment-level ids — by design).
- Vbeta: 111 ledger → 49 admitted; splits cover exactly; U/V = 49 tasks,
  admitted-only.

## Inconsistencies found and resolution

1. Checker asserted splits by bare rec_id → false overlap alarms
   (finding+exploit rows share ids). Fixed checker: (record_type, rec_id).
2. Checker asserted A-task ids ⊇ all findings → 2 "missing" were the
   quarantined dupes. Fixed checker: population = judged − quarantined.
3. Checker asserted I/J/H/T tasks resolve to finding/record ids → wrong
   populations (experiment dirs / preview rows). Fixed checker per family.
4. H commit refs → proven to be `experiment_id` in leg result files;
   checker asserts the linkage.
5. Test fixtures contained 3 authoring bugs (bad overlap/gap/leak
   expectations, space-vs-underscore term). Fixed fixtures, not validators.
6. No dataset inconsistency found: 119/119 manifest checks, 16
   reproducibility checks (14 pass, 2 honest `skipped_no_network`), all authorship
   gates green, README/stats `--check` current.

## PASS / FAIL / SKIPPED matrix

| Command | Result |
|---|---|
| scripts/check_manifests.py | PASS (119/119) |
| scripts/check_reproducibility.py | PASS (14 pass, 2 SKIPPED) |
| tests/ (44) | PASS |
| scripts/validate.py | PASS (71/71) |
| scripts/validate_v3.py | PASS (33/33) |
| scripts/validate_v31.py | PASS (32/32) |
| Vbeta build --check / gate / tests | PASS |
| generate_stats.py --check | PASS (current) |
| generate_readme.py --check | PASS (current) |
| build_all.py --with-network | SKIPPED (skipped_no_network: needs clones, forge, archive RPC) |
| source-pin object resolution | SKIPPED (skipped_no_network; 40-hex format verified) |

No stale manifests. No README changes (generator-agreement holds).
Vbeta isolation intact (sentinels match `present_snapshot.json`).

## Published limitations (measured, enforced by gates)

- Split-overlap metrics (`scripts/check_manifests.py`, leakage section):
  taxonomy-class Jaccard train×validation 0.647, train×test **0.625**,
  validation×test 0.545; contract-name Jaccard 0.013–0.026; **0** shared
  normalized titles and **0** shared code files across splits. Shared
  classes are normal (same taxonomy everywhere); shared files would fail.
- Near-duplicate templates: 51 title clusters (115 rows) in the Solodit
  harvest at ≥0.85 token Jaccard (e.g. Hats findings republished under two
  finding-IDs); first occurrence kept, 63 quarantined as CORROBORATION_ONLY
  with links in `derived_vbeta/duplicates.jsonl`. PoC-preferring keep rule:
  no quoted PoC is discarded with its row.
- Per-field coverage (`reports/field_coverage.md`, regenerated
  `scripts/field_coverage.py`): v1 root_cause 5/264 (1.9%), attacker model
  290/722 known, Vbeta severity 118/719 (16.4%), v3 root_cause/impact 0%.
- Benchmark scoring: 10,103 exactly-scorable tasks at micro 0.7296
  (majority) / 0.3671 (random-seed7); B/D/G/H/Q excluded with reasons
  (`docs/RUBRIC.md`, `docs/ANSWER_KEY.md`, `reports/baselines/`).
- `work/` posture: manifests never require `work/`; **133** shipped data
  rows cite git-ignored payloads as provenance notes (117 `jsonl_ml`
  list_endpoint notes + 16 benchmark L/P/Q input notes), pinned by
  `check_manifests.py`. Each citing row's usable content is inline; the
  raw advisory payloads are re-fetchable from GHSA/NVD APIs but no in-repo
  builder restores them (only `build_vyper_ml.py --fetch` does, for vyper).
- Scrape artefacts (`nextdata/`, `.firecrawl/`) are git-ignored local-only
  space, enforced by `check_reproducibility.py`; 1,192 of 1,926 issues
  still unscraped (credits), queued behind resume tooling.
