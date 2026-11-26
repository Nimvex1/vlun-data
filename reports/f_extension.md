# VLUN F-extension: rejection evidence and duplicate radar

Built by `scripts/build_f_extension.py` at `vlun-f-extension/2.0` from 444 canonical rejection-corpus records.

## F-A six-axis rejection evidence

- task rows: 444 over 444 distinct submissions
- scorable (every axis assessable): 9
- partial (some axes unassessable): 435
- rows carrying a technical explanation of falsity: 6
- splits: {'train': 228, 'validation': 179, 'test': 37}

| axis | coverage | supported | unknown | majority baseline | evidence given in packet |
| --- | --- | --- | --- | --- | --- |
| `rejection_status_publicly_reported` | 444 | 1.000 | 0.000 | 1.000 | yes |
| `reason_attributed_to_judge_or_sponsor` | 9 | 1.000 | 0.000 | 1.000 | no |
| `reason_supported_by_cited_code` | 288 | 0.004 | 0.000 | 0.997 | no |
| `claim_corroborated_as_duplicate_of_confirmed_finding` | 444 | 0.423 | 0.000 | 0.577 | yes |
| `exploit_attempted_and_claimed_violation_not_demonstrated` | 444 | 0.000 | 0.000 | 1.000 | yes |
| `unknown_or_insufficient_evidence` | 444 | 0.556 | 0.000 | 0.556 | no |

An axis whose evidence is given in the packet is answered by reading, not by triage: the majority baseline is published so a headline accuracy over these axes cannot be mistaken for judgement. The discriminating axes are the attributed-reason, code-supported and unknown axes, plus the field that says which supported axes are technical explanations of falsity.

Axis totals overlap. They are not additive and must not be summed.

## F-B pre-submission duplicate radar

- pairs: 632
- confirmed duplicate pairs (published pointer resolves): 179
- rule-derived distinct pairs (disjoint targets AND a recorded root-cause difference; no human adjudication): 39
- ambiguous class: 414
- label tiers: {'rule_derived_target_and_root_cause_negative': 39, 'pointer_supported_positive': 179, 'ambiguous_target_separation_without_root_cause': 275, 'ambiguous_shared_target_no_pointer': 139}
- label cohorts: {'primary': 357, 'exploratory': 275}
- pairs whose pointer does not resolve (unscorable): 0
- unique candidate submissions: 410
- unique canonical findings: 122
- by split: {'test': 56, 'train': 309, 'validation': 267}
- pointer evidence across the corpus: {'pointer_names_an_unresolved_issue': 143, 'explicit_pointer': 188, 'no_duplicate_pointer_at_all': 113}
- records that can yield no positive pair (no pointer, or a pointer to an issue this dataset cannot resolve): 256
- blocked pair shapes: {'cross_file_separation_without_root_cause_evidence': 18027, 'shared_function_target': 797, 'same_root_cause_label': 82}

## Split integrity

The extension inherits the published `splits_v2` assignment. Clusters (submission + its canonical finding + its audit) number 8 over 693 members; 0 clusters straddle a split and 0 of 8 audits do. Any F-B pair whose two sides would land on different splits is dropped rather than shipped: 0 pairs so far.

Independent audit projects in the corpus: 5 (2022-05-alchemix 32, 2024-01-decent 83, 2024-01-renft 96, 2024-04-noya 196, 2024-08-wildcat 37).

## Limits

- no independent human adjudication sample was collected for this extension, so no inter-annotator agreement is claimed anywhere in these numbers; the gold is the documented rule applied to public evidence, and the published floors are what a trivial predictor reaches on the same denominators,
- F-A `observed_code_structure` is projected from `derived/hard_negatives.jsonl`; that layer rebuilds byte-identically (re-verified 2026-10-24: `python scripts/build_hard_negatives.py` reproduces the committed file exactly), so a change to it must be rebuilt into the F-A packets with `python scripts/build_f_extension.py`
- the pool is drawn from public Code4rena contest records, so the underlying statuses are memorizable; this is an open-key evaluation, not a holdout,
- with the projects available here a project-held-out split is not credible and is not claimed,
- manifest scorable counts: F-A 9, F-B 632.
