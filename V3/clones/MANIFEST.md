# V3/clones — manifest (shallow, metadata-only for PDFs)

Cloned 2026-10-06, `git clone --depth 1`. No history beyond HEAD. Third-party PDFs
are present as vendored blobs inside these git checkouts (as published by the auditor);
VLUN ingestion must still treat them METADATA_ONLY (link + sha256 + attributed facts).

## Cloned (18) — dir | HEAD | remote

| dir | HEAD | remote |
|---|---|---|
| abdk-audits | 57af593 | https://github.com/abdk-consulting/audits |
| ackee-audits | 2033ac4 | https://github.com/Ackee-Blockchain/public-audit-reports |
| anza-security-audits | 4d5d71e | https://github.com/anza-xyz/security-audits |
| c4-phi-findings | 0c473d9 | https://github.com/code-423n4/2024-08-phi-findings |
| c4-renzo-findings | b4206ce | https://github.com/code-423n4/2024-04-renzo-findings |
| c4-reserve-findings | 59b95d6 | https://github.com/code-423n4/2024-07-reserve-findings |
| certora-reports | 646989b | https://github.com/Certora/SecurityReports |
| cyba-audits | 7b74efd | https://github.com/cybasecurity/audits |
| defihacklabs | 0200ce8 | https://github.com/SunWeb3Sec/DeFiHackLabs |
| hexens-reports | beb987e | https://github.com/Hexens/Smart-Contract-Review-Public-Reports |
| informal-audits | 39db31f | https://github.com/informalsystems/audits |
| nethermind-audits | abf4dd7 | https://github.com/NethermindEth/PublicAuditReports |
| pashov-audits | 8d9785a | https://github.com/pashov/audits |
| sherlock-optimism | 3907084 | https://github.com/sherlock-audit/2023-01-optimism-judging |
| sherlock-symmetrical | 5b2c754 | https://github.com/sherlock-audit/2024-06-symmetrical-update-2-judging |
| sigmaprime-audits | 7d9046e | https://github.com/sigp/public-audits |
| smartbugs-curated | 230e649 | https://github.com/smartbugs/smartbugs-curated |
| zellic-publications | 0aa77a8 | https://github.com/Zellic/publications |

Total on disk at clone time: ~2992 MB (PDF-heavy: zellic/hexens/nethermind/certora).
Re-verify with: `git -C <dir> rev-parse HEAD` + `(Get-ChildItem V3/clones -Recurse -File | Measure Length -Sum)`.

## NOT cloned — pointer only (per your metadata-only choice)

| source | pointer | reason |
|---|---|---|
| Cantina | https://cantina.xyz/portfolio | no single git repo; per-review pages + cdn.cantina.xyz PDFs |
| Immunefi disclosures | https://reports.immunefi.com + https://immunefi.com/blog/bug-fix-reviews/ | report pages, not a repo |
| Veridise ZK | https://veridise.com/audits-archive/zero-knowledge-security/ | site + per-report PDFs, no repo |
| Runtime Verification | https://runtimeverification.com/work | per-report pages + PDFs |
| OtterSec | https://osec.io/audits | site; code at https://github.com/otter-sec (tools, not reports) |
| Neodyme | https://neodyme.io/reports/ | site PDFs only |
| SlowMist Hacked | https://hacked.slowmist.io/ | incident DB, triage only |
| BlockSec Phalcon | https://blocksec.com/security-incident | incident DB + blogs |
| Quantstamp scattered | https://quantstamp.com/audits + certificate.quantstamp.com | harvest per client repo |
| Code4rena (rest) | https://github.com/code-423n4 (3 samples cloned) | org has 100s of contests; extend per-need |
| Sherlock (rest) | https://github.com/sherlock-audit (2 samples cloned) | same; use reconciling-contests rule (see 02_source_dossiers.md) |

## Suggested next step (not done here)

Build ONE contest pipeline on the 5 samples (scope commit → judged H/M → fix link →
QA/low negatives), then fan out to the orgs. Keep splits by source-repo (no source spans splits).
