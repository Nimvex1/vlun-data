# Field coverage — what fraction of records carry each field

Counts recomputed from canonical files by `scripts/field_coverage.py`. `unknown`/empty/null counts as missing; nothing is inferred.

| Scope.field | Total | Known | Missing | Known % |
|---|---|---|---|---|
| `v1.derived.attacker_model.attacker_identity` | 685 | 399 | 286 | 58.2 |
| `v1.derived.invariants` | 685 | 685 | 0 | 100.0 |
| `v1.derived.security_state_transition` | 685 | 685 | 0 | 100.0 |
| `v1.derived.taxonomy` | 685 | 685 | 0 | 100.0 |
| `v1.findings.finding.root_cause` | 241 | 4 | 237 | 1.7 |
| `v1.findings.finding.severity` | 241 | 241 | 0 | 100.0 |
| `v1.findings.finding.status` | 241 | 241 | 0 | 100.0 |
| `v1.findings.finding.summary` | 241 | 199 | 42 | 82.6 |
| `v1.findings.finding.title` | 241 | 241 | 0 | 100.0 |
| `v1.findings.finding.vulnerability_classes` | 241 | 230 | 11 | 95.4 |
| `v3.records.attack_sequence` | 4623 | 0 | 4623 | 0.0 |
| `v3.records.ecosystem` | 4623 | 4623 | 0 | 100.0 |
| `v3.records.fix_description` | 4623 | 0 | 4623 | 0.0 |
| `v3.records.impact` | 4623 | 0 | 4623 | 0.0 |
| `v3.records.language` | 4623 | 4623 | 0 | 100.0 |
| `v3.records.root_cause` | 4623 | 4623 | 0 | 100.0 |
| `v3.records.severity` | 4623 | 3755 | 868 | 81.2 |
| `vbeta.records.attack_sequence` | 80 | 0 | 80 | 0.0 |
| `vbeta.records.decision` | 80 | 80 | 0 | 100.0 |
| `vbeta.records.ecosystem` | 80 | 74 | 6 | 92.5 |
| `vbeta.records.fix_description` | 80 | 0 | 80 | 0.0 |
| `vbeta.records.impact` | 80 | 0 | 80 | 0.0 |
| `vbeta.records.language` | 80 | 80 | 0 | 100.0 |
| `vbeta.records.root_cause` | 80 | 0 | 80 | 0.0 |
| `vbeta.records.severity_observed` | 80 | 0 | 80 | 0.0 |
| `vbeta.records.status_observed` | 80 | 9 | 71 | 11.2 |
| `vbeta.records.title` | 80 | 80 | 0 | 100.0 |
| `vbeta.records.verification_level` | 80 | 80 | 0 | 100.0 |
