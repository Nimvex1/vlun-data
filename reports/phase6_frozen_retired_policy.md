# Phase 6 — frozen retired benchmark files: gate-policy decision and fix

## Decision

Apply the **same narrow, documented exact-file exemption** that
`scripts/check_manifests.py` already uses (`_FROZEN_RETIRED_V22_FILES`) to
`scripts/validate_checks.py::check_v22_layer`, check #7
(`benchmark_rows_obey_the_row_contract`).

Only the six published byte-identical retired v2.2 task files
(`benchmark/retired_families/{K,L,M,N,O,P}_*.jsonl`) are exempted, and only
from the **one** comparison that resolves a row's id/split against the live
61-record `derived_v2_2` layer (`seen_split.get(rec_id_part) != {r.get("split")}`).

## Justification

- Each `benchmark/retired_families/<family>.retirement.json` states *"data
  preserved byte-identical"*. Those files are contractually frozen artifacts.
- `scripts/check_manifests.py` already exempts these exact files from its three
  current-id comparisons (lines 41–66 and 496–544), with a full written
  rationale: hydration legitimately shrank the live `derived_v2_2` layer from
  137/37 rows to 61, so the frozen ids no longer resolve against current data.
- Rewriting the retired files would destroy the byte-identical provenance the
  retirement records promise. Re-adding the purged records to the live layer
  would fabricate trainable data. Neither is acceptable.
- The exemption is keyed to the **exact manifest `file` path**, not to a family
  name or layer, so it cannot expand to a future live file. Q is a live v2.2
  family (`benchmark/Q_evidence_type_and_quality_rubric.jsonl`, 61 tasks) and
  remains fully validated.
- Every retired row is still read, scanned and counted (722 rows are tallied
  and disclosed in the check's `detail` string: 137×5 + 37 = 722). Every
  **other** row-contract field is still validated on those rows: id carries
  key+split, `task`, `answer_key_status` vocabulary, `evidence_type`
  vocabulary, `split` vocabulary, `unlabelled_reason` consistency, `layer=v2.2`,
  `answer_key_evidence_level` vocabulary, and the unlabeled/level consistency
  rule. No global weakening.

## Exact diff

```diff
diff --git a/scripts/validate_checks.py b/scripts/validate_checks.py
index fb95601..40f273c 100644
--- a/scripts/validate_checks.py
+++ b/scripts/validate_checks.py
@@ -1007,6 +1007,36 @@ def check_v22(rep):
                    "version from scripts/vlun.py; this check catches a stale copy")
 
 
+# Exact-file exemption for PUBLISHED FROZEN ARTIFACTS (not a family-wide rule).
+# Families K-P were retired with their rows preserved byte-identical: each
+# benchmark/retired_families/<family>.retirement.json states "data preserved
+# byte-identical". Their `split` fields and id references are therefore pinned
+# at the ORIGINAL 137-row derived_v2_2 population (M at 37 rows). Hydration
+# legitimately shrank the live derived_v2_2 layer to 61 records, so a frozen
+# file's ids no longer resolve against -- nor equal -- the current ids.
+# Rewriting these files would destroy the byte-identical provenance the
+# retirement records promise, and re-adding purged records would fabricate
+# trainable data; neither is an option.
+#
+# This mirrors the exact-file set already used by scripts/check_manifests.py::
+# _FROZEN_RETIRED_V22_FILES for its three current-id comparisons. We exempt
+# ONLY these exact files, and ONLY from the live-layer split-resolution
+# comparison in v2.2 row-contract check #7. Every retired row is still read,
+# scanned and counted, and every OTHER row-contract field (id carries key+split,
+# task, status/evidence vocabularies, unlabelled_reason, layer=v2.2,
+# answer_key_evidence_level vocabulary) is still validated on it. Q is a LIVE
+# v2.2 family and is NOT exempt: it is still compared to splits_v2_2. Every
+# non-retired family is validated strictly -- no global weakening.
+_FROZEN_RETIRED_V22_FILES = frozenset({
+    "benchmark/retired_families/K_language_ecosystem_routing.jsonl",
+    "benchmark/retired_families/L_severity_reconciliation.jsonl",
+    "benchmark/retired_families/M_experiment_level_classification.jsonl",
+    "benchmark/retired_families/N_attacker_identity_extraction.jsonl",
+    "benchmark/retired_families/O_record_class_and_scope.jsonl",
+    "benchmark/retired_families/P_provenance_tier_and_rights.jsonl",
+})
+
+
 def check_v22_layer(rep):
     """v2.2 layer-integrity checks."""
     # ---------------------------------------------------- v2.2 layer integrity
@@ -1207,11 +1237,17 @@ def check_v22_layer(rep):
     # 7. every row of every family obeys the shared row contract
     STATUS_VOCAB = {"labeled", "partial", "unlabeled", "unscorable"}
     row_bad = []
+    frozen_rows = 0
     for key, (name, layer, _q) in BENCHMARK_FAMILIES.items():
         f = _task_file(name)
         if not f.exists():
             continue
+        _entry = tasks_manifest.get(name)
+        _rel = _entry.get("file") if isinstance(_entry, dict) else None
+        _frozen = _rel in _FROZEN_RETIRED_V22_FILES
         for r in read_jsonl(f):
+            if _frozen:
+                frozen_rows += 1
             rid = r.get("id") or ""
             if not rid.startswith(f"{key}::{r.get('split')}::"):
                 row_bad.append(f"{name} {rid} id does not carry its key and split")
@@ -1235,7 +1271,14 @@ def check_v22_layer(rep):
                 if r.get("answer_key_evidence_level") not in EV:
                     row_bad.append(f"{name} {rid} "
                                    f"answer_key_evidence_level={r.get('answer_key_evidence_level')!r}")
-                if seen_split.get(rec_id_part) != {r.get("split")}:
+                # Exact-file exemption: only the byte-identical retired K-P
+                # artifacts are excused from this ONE live-layer comparison.
+                # Their split/ids are frozen at the original 137/37-row
+                # population and no longer resolve against the 61-record live
+                # layer; see _FROZEN_RETIRED_V22_FILES. Every non-retired v2.2
+                # family (including Q) and every other row-contract field is
+                # still checked strictly.
+                if not _frozen and seen_split.get(rec_id_part) != {r.get("split")}:
                     row_bad.append(f"{name} {rid} split disagrees with splits_v2_2")
                 # Independent check, never elif'd onto the one above: an
                 # unlabeled row typed anything but unknown would otherwise
@@ -1247,7 +1290,13 @@ def check_v22_layer(rep):
     rep.add("v2.2", "benchmark_rows_obey_the_row_contract", not row_bad, row_bad,
             detail="applies to families A-Q: ids carry key+split, statuses and "
                    "evidence types are in the closed vocabularies, unlabelled "
-                   "rows state why, and v2.2 rows resolve against splits_v2_2")
+                   "rows state why, and v2.2 rows resolve against splits_v2_2. "
+                   f"EXEMPT (frozen byte-identical retired artifacts): "
+                   f"{frozen_rows} rows across {len(_FROZEN_RETIRED_V22_FILES)} "
+                   f"exact files (K/L/M/N/O/P) are exempt ONLY from the "
+                   f"live-layer split-resolution comparison; every other "
+                   f"row-contract field is still validated on them, and Q "
+                   f"plus every non-retired family is validated strictly")
 
     # 8. the strongest possible check: rebuild every LIVE v2.2 family from the
     #    records and require byte-equality with what is on disk, so a stale or
```

## Proof the exemption is narrow (in-memory probes, no files touched)

| Probe | Result |
| --- | --- |
| Exemption in place | `ok=True`, **0** violations; 722 frozen rows disclosed in `detail` |
| Exemption removed in-memory (`_FROZEN_RETIRED_V22_FILES = frozenset()`) | `ok=False`, **424** violations — K=84, L=84, M=4, N=84, O=84, P=84; **all 424** are `split disagrees with splits_v2_2` |
| Exemption kept, synthetic bad id planted in **live Q** | `ok=False`, **1** violation: `Q_evidence_type_and_quality_rubric Q::train::SYNTHETIC-NONEXISTENT-ID split disagrees with splits_v2_2` — non-retired live-layer resolution still enforced |
| Exemption kept, synthetic bad `answer_key_status` planted in **frozen K** | `ok=False`, **1** violation: `K_language_ecosystem_routing ... status='SYNTHETIC_BAD_STATUS'` — other fields still enforced on frozen rows |

The 424 re-appear exactly when the exemption is removed, and only the six
exact retired files are affected. This proves no global weakening.

## Gate results (exact observed counts)

Baseline before the change (this checkout):

```
80/85 checks passed; 4 critical failures, 1 warnings
  CRITICAL: structure/cross_file_id_references_resolve (1)
  CRITICAL: v2.2/experiment_index_is_exactly_the_referenced_set (3)
  CRITICAL: v2.2/benchmark_rows_obey_the_row_contract (424)
  CRITICAL: v2.2/family_M_is_exactly_the_set_of_executed_records (3)
```

After the change:

```
$ python scripts/validate.py --quiet
81/85 checks passed; 3 critical failures, 1 warnings
  CRITICAL: structure/cross_file_id_references_resolve (1)
  CRITICAL: v2.2/experiment_index_is_exactly_the_referenced_set (3)
  CRITICAL: v2.2/family_M_is_exactly_the_set_of_executed_records (3)
```

`v2.2/benchmark_rows_obey_the_row_contract` **cleared** (424 → 0). The three
remaining criticals are separate checks outside this task's ownership and are
unchanged by this diff.

```
$ python scripts/check_manifests.py --quiet
checked=181 pass=181 fail=0 unknown=0

$ python -m pytest -q tests/test_benchmark_status.py
...........................                                              [100%]
27 passed in 31.55s
```

No benchmark retired file, dataset, or test was modified.
