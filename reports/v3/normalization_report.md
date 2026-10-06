# V3.1 normalization report

normalization_version 3.1 (dataset 3.0). V3.0 files untouched; this layer is fragments + overlays + preview.

## Coverage (evidence, not scans)

fragments admitted: 7037 / 29176
fragment decisions: {'admitted': 7037, 'rejected_no_boundary': 718, 'rejected_bad_title': 3436, 'rejected_no_severity': 9892, 'rejected_poor_extraction': 235, 'duplicate_native_id': 7858, 'rejected_duplicate': 7858}
overlays: 9744 (conflicts kept, old values win: 0)
preview rows: 12504
patch candidates (all not_testable): 47

## Confidence distributions
severity: {'explicit': 4231, 'derived': 2806, 'unknown': 9892}
taxonomy: {'unknown': 4944, 'derived': 1497, 'explicit': 596}
language/ecosystem: {'unknown': 3622, 'derived': 1526, 'explicit': 1889}
commit roles: {'fix': 6, 'scope': 20, 'unknown': 4}

## Extraction quality
{'text_cmap': 1394, 'despaced_reports': 133, 'text_naive': 174, 'no_body_offline': 1107, 'dhl_attack_sequence': 878, 'text_markdown': 281, 'md_code_files': 3130, 'overlay_superseded': 6137, 'corroboration_links': 0, 'patch_candidates': 47, 'preview_rows': 12504}

## Splitter use
{'_split_abdk': 191, '_split_generic_severity': 407, '_split_anza': 68, '_split_certora': 192, '_split_cyba': 14, '_split_nethermind': 190, '_split_sigmaprime': 154, '_split_zellic': 392}

## Per-source yield (admitted / rejected fragments)

Source | Admitted | Rejected
---|---|---
abdk-audits | 2872 | 4590
ackee-audits | 0 | 96
anza-security-audits | 22 | 441
certora-reports | 21 | 2029
cyba-audits | 44 | 17
hexens-reports | 0 | 202
informal-audits | 0 | 94
nethermind-audits | 708 | 1184
pashov-audits | 0 | 3
sherlock-optimism | 0 | 218
sherlock-symmetrical | 0 | 1
sigmaprime-audits | 1081 | 856
zellic-publications | 2289 | 12408

## Coverage BEFORE (v3.0 ledger) -> AFTER (v3.1)

Metric | Before | After
---|---|---
rows | 7712 | 12504
severity_known | 4717 | 11610
class_known | 207 | 2093
language_known | 6640 | 8882
ecosystem_known | 6668 | 8507
repository_known | 4940 | 4520
exact_vulnerable_commits | 1205 | 1077
exact_fixed_commits | 47 | 47
affected_files | 207 | 5790
affected_functions | - | 0
line_refs | - | 213
published_pocs | 881 | 1700
executable_pocs | - | 0
experiment_ready_tier_a | - | 0
executed_pocs | - | 0
reproduced | - | 0
l5 | - | 0
l6 | - | 0
patch_candidates | - | 47
patches_verified | - | 0

AFTER counts preview rows (v3.0 records with overlays applied + admitted V3.1 children). repository_known and exact commits read lower than Before because preview excludes non-admitted ledger rows (e.g. C4 scope commits on QA/research rows); no committed value was changed. Executed/reproduced/L5/L6 stay 0: nothing was executed in V3.1.
