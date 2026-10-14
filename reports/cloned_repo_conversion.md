# Cloned Repository Conversion — Staging Report

Generated: 2026-10-14
Scope: staging-only. No canonical VLUN records, manifests, splits, or benchmarks were modified.

## Input repositories

| Source ID | Repository | Git SHA | Local clone | PDFs staged |
|---|---|---:|---|---:|
| `halborn_public_reports` | https://github.com/HalbornSecurity/PublicReports | `4f3d1c6451ac01ba669a43072dd30b857ef9aa90` | `work/new_sources/halborn_reports` | 282 |
| `oak_security_audit_reports` | https://github.com/oak-security/audit-reports | `00ad9f3fb9d9e62c711414777741dc588685fb56` | `work/new_sources/oak_audit_reports` | 316 |
| `coinfabrik_audit_reports` | https://github.com/CoinFabrik/coinfabrik-audit-reports | `051bbc276c90a0bd73295ec5dcd8b0da295141f8` | `work/new_sources/coinfabrik_reports` | 68 |

Total report-level candidates staged: **666**.
Observed-commit regex hits across extracted report text: **44**. Affected-repository regex hits: **0**.
No PDFs were fully parsed for findings in this pass.

## Instantiated files

- `work/new_sources_intake_manifest.json` (cloned + web-only source inventory)
- `work/cloned_conversion/staged_report_candidates.jsonl` (666 staged report candidates)
- `reports/cloned_repo_conversion.md` (this file)
- `tests/test_cloned_conversion.py` (6 tests)
- `work/stage_cloned_reports.py` (idempotent staging generator; stdlib + pypdf)

## Evidence status

All 666 records are `CANDIDATE_REPORT_ONLY`, verification level `L0`, `admitted=false`.
No PoCs were compiled or executed. No severity, title, finding, project-scope, or vulnerable-revision claims were extracted except 44 regex-observed commit strings, which remain attributed (not verified) report text.
Web-only sources from the discovery phase are not staged:
`blocksec`, `quantstamp`, `immunefi`, `slowmist_hacked`, `rekt`, `defillama`, `hats`.
`tintinweb/smart-contract-vulndb`, `sirhashalot/SCV-List`, `ASSERT-KTH/PoPoC`, and `nikitastupin/public-audit-reports-data` were inventoried but not converted in this pass.
`ASSERT-KTH/PoPoC` is excluded from automated conversion because its working tree did not check out locally (all 399 tracked files remain deleted in the worktree).

## Validation

Command:

```text
python -m unittest tests.test_cloned_conversion
```

Result: **6 tests passed** (schema completeness, unique candidate IDs, decision/level invariants, staging counts, SHA-256 lengths).

PoC checks were not run: `skipped_no_network`/not applicable. No experimental verification was claimed.

## Known limitations and licensing

- `halborn_public_reports` and `coinfabrik_audit_reports`: no `LICENSE` file found in their cloned trees. Reuse terms unverified.
- `oak_security_audit_reports`: `LICENSE.md` begins `# Creative Commons Attribution-NoDerivatives 4.0 International`.
- Full report text, finding severities, exact affected code spans, commit revisions, and PoC locations were not extracted beyond regex surface pointers.
- Report PDFs are inventoried and hashed; repository commit (Git SHA above) is pinned for provenance.
- No deduplication against existing VLUN source IDs beyond source-level non-overlap was performed; finding-level dedup is blocked until findings are extracted.

## Next required work

1. Implement firm-report parsers (section-level) for Halborn/Oak/CoinFabrik report templates.
2. Extract per-finding title, severity, affected repository/commit, function, impact, fix status, and any quoted PoC text.
3. Re-run occurrence/commit pointer resolution against Cloned clone directories or cited protocol repositories.
4. Execute only those PoCs with reproducible environments in isolated `work/` directories; mark L3/L4/L5/L6 only with run artefacts.
5. Deduplicate by source URL, protocol alias, code hash, affected function, and vulnerability class against `jsonl_ml/`, `jsonl_v3/`, and `Vbeta/` records.
6. Keep findings, hard negatives, and quarantine decisions separate; do not promote report candidates into canonical datasets until staged tests and manifest gates pass.