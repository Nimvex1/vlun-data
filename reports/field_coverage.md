# Field coverage — what fraction of records carry each field

Counts recomputed from canonical files by `scripts/field_coverage.py`. `unknown`/empty/null counts as missing; nothing is inferred.

| Scope.field | Total | Known | Missing | Known % |
|---|---|---|---|---|
| `v1.derived.attacker_model.attacker_identity` | 722 | 290 | 432 | 40.2 |
| `v1.derived.invariants` | 722 | 722 | 0 | 100.0 |
| `v1.derived.security_state_transition` | 722 | 722 | 0 | 100.0 |
| `v1.derived.taxonomy` | 722 | 722 | 0 | 100.0 |
| `v1.findings.finding.root_cause` | 264 | 5 | 259 | 1.9 |
| `v1.findings.finding.severity` | 264 | 264 | 0 | 100.0 |
| `v1.findings.finding.status` | 264 | 264 | 0 | 100.0 |
| `v1.findings.finding.summary` | 264 | 220 | 44 | 83.3 |
| `v1.findings.finding.title` | 264 | 264 | 0 | 100.0 |
| `v1.findings.finding.vulnerability_classes` | 264 | 249 | 15 | 94.3 |
| `v3.records.attack_sequence` | 5467 | 0 | 5467 | 0.0 |
| `v3.records.ecosystem` | 5467 | 5467 | 0 | 100.0 |
| `v3.records.fix_description` | 5467 | 0 | 5467 | 0.0 |
| `v3.records.impact` | 5467 | 0 | 5467 | 0.0 |
| `v3.records.language` | 5467 | 5467 | 0 | 100.0 |
| `v3.records.root_cause` | 5467 | 0 | 5467 | 0.0 |
| `v3.records.severity` | 5467 | 4573 | 894 | 83.6 |
| `vbeta.records.attack_sequence` | 6935 | 0 | 6935 | 0.0 |
| `vbeta.records.decision` | 6935 | 6935 | 0 | 100.0 |
| `vbeta.records.ecosystem` | 6935 | 6123 | 812 | 88.3 |
| `vbeta.records.fix_description` | 6935 | 0 | 6935 | 0.0 |
| `vbeta.records.impact` | 6935 | 0 | 6935 | 0.0 |
| `vbeta.records.language` | 6935 | 6218 | 717 | 89.7 |
| `vbeta.records.root_cause` | 6935 | 0 | 6935 | 0.0 |
| `vbeta.records.severity_observed` | 6935 | 6317 | 618 | 91.1 |
| `vbeta.records.status_observed` | 6935 | 91 | 6844 | 1.3 |
| `vbeta.records.title` | 6935 | 6935 | 0 | 100.0 |
| `vbeta.records.verification_level` | 6935 | 6935 | 0 | 100.0 |
