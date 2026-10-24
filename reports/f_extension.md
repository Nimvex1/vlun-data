# VLUN F-extension: rejection evidence and duplicate radar

Built by `scripts/build_f_extension.py` at `vlun-f-extension/1.0` from 458 canonical rejection-corpus records.

## F-A six-axis rejection evidence

- task rows: 458 over 458 distinct submissions
- scorable (every axis assessable): 292
- partial (some axes unassessable): 166
- rows carrying a technical explanation of falsity: 6
- splits: {'train': 232, 'validation': 188, 'test': 38}

| axis | coverage | supported | unknown | majority baseline | evidence given in packet |
| --- | --- | --- | --- | --- | --- |
| `rejection_status_publicly_reported` | 458 | 1.000 | 0.000 | 1.000 | yes |
| `reason_attributed_to_judge_or_sponsor` | 458 | 0.020 | 0.000 | 0.980 | no |
| `reason_supported_by_cited_code` | 292 | 0.003 | 0.000 | 0.997 | no |
| `claim_corroborated_as_duplicate_of_confirmed_finding` | 458 | 0.421 | 0.000 | 0.579 | yes |
| `exploit_attempted_and_claimed_violation_not_demonstrated` | 458 | 0.000 | 0.000 | 1.000 | yes |
| `unknown_or_insufficient_evidence` | 458 | 0.559 | 0.000 | 0.559 | no |

An axis whose evidence is given in the packet is answered by reading, not by triage: the majority baseline is published so a headline accuracy over these axes cannot be mistaken for judgement. The discriminating axes are the attributed-reason, code-supported and unknown axes, plus the field that says which supported axes are technical explanations of falsity.

Axis totals overlap. They are not additive and must not be summed.

## F-B pre-submission duplicate radar

- pairs: 553
- confirmed duplicate pairs: 184
- adjudicated distinct pairs: 258
- ambiguous class: 111
- pairs whose pointer does not resolve (unscorable): 0
- unique candidate submissions: 386
- unique canonical findings: 119
- by split: {'test': 31, 'train': 323, 'validation': 199}
- pointer evidence across the corpus: {'pointer_names_an_unresolved_issue': 145, 'explicit_pointer': 193, 'no_duplicate_pointer_at_all': 120}
- records that can yield no positive pair (no pointer, or a pointer to an issue this dataset cannot resolve): 265
- blocked pair shapes: {'cross_file_separation_without_root_cause_evidence': 16510, 'shared_function_target': 501, 'same_root_cause_label': 542}

## Split integrity

The extension inherits the published `splits_v2` assignment. Clusters (submission + its canonical finding + its audit) number 8 over 730 members; 0 clusters straddle a split and 0 of 8 audits do. Any F-B pair whose two sides would land on different splits is dropped rather than shipped: 0 pairs so far.

Independent audit projects in the corpus: 5 (2022-05-alchemix 33, 2024-01-decent 88, 2024-01-renft 100, 2024-04-noya 199, 2024-08-wildcat 38).

## Limits

- no independent human adjudication sample was collected for this extension, so no inter-annotator agreement is claimed anywhere in these numbers; the gold is the documented rule applied to public evidence, and the published floors are what a trivial predictor reaches on the same denominators,
- F-A `observed_code_structure` is projected from `derived/hard_negatives.jsonl`, a layer with a known non-reproducible field (`observed_code_facts[].guards` shape differs between the shipped rows and a rebuild, `check_reproducibility.py` fails it on 8 records): if that layer is regenerated, F-A packets change and must be rebuilt with it,
- the pool is drawn from public Code4rena contest records, so the underlying statuses are memorizable; this is an open-key evaluation, not a holdout,
- with the projects available here a project-held-out split is not credible and is not claimed,
- manifest scorable counts: F-A 292, F-B 553.
