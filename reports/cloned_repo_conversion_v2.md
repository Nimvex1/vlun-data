# Cloned Repository Conversion v2 — V4 Registration Report

Generated: 2026-10-14
Scope: new isolated VLUN V4 layer from the 666 cloned report candidates. No canonical `jsonl/`, `derived/`, `jsonl_ml/`, `jsonl_v3/`, or `Vbeta` records were rewritten.

## Source repositories and revisions

| Source ID | Repository | Git SHA | PDFs |
|---|---|---|---:|
| `halborn_public_reports` | https://github.com/HalbornSecurity/PublicReports | `4f3d1c6451ac01ba669a43072dd30b857ef9aa90` | 282 |
| `oak_security_audit_reports` | https://github.com/oak-security/audit-reports | `00ad9f3fb9d9e62c711414777741dc588685fb56` | 316 |
| `coinfabrik_audit_reports` | https://github.com/CoinFabrik/coinfabrik-audit-reports | `051bbc276c90a0bd73295ec5dcd8b0da295141f8` | 68 |

Total staged report candidates: **666**.

## Conversion counts

| Stage | Count |
|---|---:|
| Report candidates staged | 666 |
| Extracted per-finding records | 5270 |
| Admitted (V4 findings) | 5268 |
| Quarantined | 0 |
| Duplicates | 2 |
| Rejected for missing core fields | 0 |

Per source extracted/admitted counts:

| Source ID | Extracted/Admitted |
|---|---:|
| `halborn_public_reports` | 1785 |
| `oak_security_audit_reports` | 3259 |
| `coinfabrik_audit_reports` | 226 |

## Language counts

| Language | Count |
|---|---:|
| go | 3394 |
| solidity | 1555 |
| rust | 143 |
| unknown | 155 |
| teal | 14 |
| move | 5 |
| michelson | 4 |

## Severity counts

Original severity labels are preserved (`original_severity`/`severity_reported`); normalized labels tracked alongside. Counts by reported label:

| Severity (reported) | Count |
|---|---:|
| Informational/INFORMATIONAL | 2361 |
| Minor (minor, low) | 1814 |
| Major/MEDIUM/Medium/HIGH/High | 773 |
| Critical/CRITICAL | 256 |

## Evidence levels

| Level | Count | Notes |
|---|---:|---|
| L0 | 5270 | Metadata/extracted report evidence only |
| L3+ | 0 | No compile/run artefacts were produced |
| L6 | 0 | Reserved; no qualifying records |

All records remain at L0 because no PoC was compiled or executed.

## Duplicate detection

- Existing layers checked: `jsonl/`, `jsonl_ml/`, `jsonl_v3/`, `Vbeta/`.
- Method: normalized source URL, repository, commit, affected function, and title similarity blocking.
- Duplicates found: **0**.
- Quarantined ambiguous/conflicting records: **0**.
- Quarantine is reserved for incomplete records; none of the extracted records lacked a title/severity, so all were admitted, with missing-provenance tracked separately below.

## PoC outcomes

- PoC execution: not attempted. No compile/run artefacts were created.
- Result status: `skipped_no_network`/not applicable for L3+ promotion.
- No L3, L4, L5, or L6 claims are made.

## Missing provenance and quality risks

- Records missing affected repository: 1445
- Records missing vulnerable commit: 1966
- Records missing affected location: 2216
- Records missing suggested fix: 179
- Licensing risks:
  - `halborn_public_reports`: no `LICENSE` file found in cloned tree (reuse terms unverified)
  - `coinfabrik_audit_reports`: no `LICENSE` file found in cloned tree (reuse terms unverified)
  - `oak_security_audit_reports`: `LICENSE.md` is Creative Commons Attribution-NoDerivatives 4.0 International (reuse restrictions apply)

## V4 layer files changed

- `jsonl_v4/findings.jsonl`
- `jsonl_v4/sources.jsonl`
- `derived_v4/candidate_ledger.jsonl`
- `derived_v4/admitted_ledger.jsonl`
- `derived_v4/quarantined_ledger.jsonl`
- `derived_v4/duplicate_ledger.jsonl`
- `derived_v4/manifest.json`
- `V4/manifest.json`
- `V4/sources.json`
- `scripts/extract_cloned_findings.py`
- `scripts/register_v4.py`
- `tests/test_v4_ingestion.py`
- `reports/cloned_repo_conversion_v2.md`

## V4 registration status

- Candidate ledger rows: 5270
- Admitted rows: 5270
- Quarantined rows: 0
- Duplicate rows: 0
- Verification levels: L0 only

## Exact reproduction commands

```text
python scripts/extract_cloned_findings.py
python scripts/register_v4.py
python tests/test_v4_ingestion.py
python -m unittest discover -s tests
python scripts/run_gates.py
python scripts/check_manifests.py
python scripts/check_reproducibility.py
python scripts/generate_readme.py --check
```

Staged source-of-truth input:

```text
work/cloned_conversion/staged_report_candidates.jsonl
```
