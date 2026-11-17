# VLUN V3 integration report

Dataset version 3.0 / schema 3.0.
Additive layer: v1/v2.2 artefacts untouched. Clone working trees (~3.1 GB) are NOT committed; provenance is clone-HEAD + file-sha256.

## Sources (18 discovered)

- abdk-audits: discovered=216 imported=0 negative=0 corroboration=0 research_only=216 rejected=0 levels={'L0': 216}
- ackee-audits: discovered=97 imported=0 negative=0 corroboration=0 research_only=97 rejected=0 levels={'L0': 97}
- anza-security-audits: discovered=77 imported=0 negative=0 corroboration=0 research_only=77 rejected=0 levels={'L0': 77}
- c4-phi-findings: discovered=378 imported=334 negative=0 corroboration=0 research_only=44 rejected=0 levels={'L0': 378}
- c4-renzo-findings: discovered=612 imported=575 negative=0 corroboration=9 research_only=28 rejected=0 levels={'L0': 612}
- c4-reserve-findings: discovered=117 imported=107 negative=0 corroboration=1 research_only=9 rejected=0 levels={'L0': 117}
- certora-reports: discovered=200 imported=0 negative=0 corroboration=0 research_only=200 rejected=0 levels={'L0': 200}
- cyba-audits: discovered=14 imported=0 negative=0 corroboration=0 research_only=14 rejected=0 levels={'L0': 14}
- defihacklabs: discovered=878 imported=878 negative=0 corroboration=0 research_only=0 rejected=0 levels={'L3': 115, 'L1': 751, 'L5': 5, 'L4': 7}
- hexens-reports: discovered=170 imported=0 negative=0 corroboration=0 research_only=170 rejected=0 levels={'L0': 170}
- informal-audits: discovered=95 imported=0 negative=0 corroboration=0 research_only=95 rejected=0 levels={'L0': 95}
- nethermind-audits: discovered=190 imported=0 negative=0 corroboration=0 research_only=190 rejected=0 levels={'L0': 190}
- pashov-audits: discovered=3520 imported=3517 negative=0 corroboration=0 research_only=3 rejected=0 levels={'L0': 3520}
- sherlock-optimism: discovered=306 imported=36 negative=0 corroboration=50 research_only=220 rejected=0 levels={'L0': 303, 'L1': 3}
- sherlock-symmetrical: discovered=24 imported=4 negative=16 corroboration=3 research_only=1 rejected=0 levels={'L0': 24}
- sigmaprime-audits: discovered=156 imported=0 negative=0 corroboration=1 research_only=155 rejected=0 levels={'L0': 156}
- smartbugs-curated: discovered=207 imported=0 negative=0 corroboration=0 research_only=207 rejected=0 levels={'L0': 207}
- zellic-publications: discovered=455 imported=0 negative=0 corroboration=44 research_only=411 rejected=0 levels={'L0': 455}

## Findings

candidates=7712 imported_records=5467
decisions={'RESEARCH_ONLY': 2137, 'IMPORT_AS_UNVERIFIED': 1934, 'CORROBORATION_ONLY': 108, 'IMPORT': 3517, 'IMPORT_AS_NEGATIVE': 16}

## Verification

levels={'L0': 6831, 'L3': 115, 'L1': 754, 'L5': 5, 'L4': 7}
L3+ comes from committed run artefacts (compile_sweep.json and experimental_proof.json via scripts/v32_execution.py); L5 requires claim-specific violation_evidence and is never awarded for an unexecuted or failed-for-another-reason run. L6 is never awarded in this layer.

## Ecosystems

{'unknown': 1044, 'evm': 6446, 'solana': 103, 'stacks': 4, 'cosmos': 95, 'sui': 5, 'aptos': 11, 'ton': 4}

## Languages

{'unknown': 1072, 'solidity': 6446, 'rust': 132, 'clarity': 4, 'go': 28, 'move': 30}

## Vulnerability classes (normalized)

{'unknown': 7505, 'Reentrancy': 32, 'Unchecked Low-Level Call': 75, 'Arithmetic': 23, 'Front-running': 7, 'Access Control': 21, 'Denial of Service': 7, 'Randomness': 31, 'Other': 3, 'Time Manipulation': 7, 'Short Address': 1}
Original per-record classes preserved in `original_vulnerability_class`.

## Provenance

exact (40-hex) vulnerable commits: 1205
exact (40-hex) fixed commits: 47
everything else: unknown (marked, never inferred).

## Licensing

METADATA_ONLY for all 18 sources: link + sha256 + attributed facts; no third-party report text redistributed.
Per-record licence fields stay `unknown` until a per-report licence is confirmed.

## Experimental verification

candidate_artefacts=127 executed=12 L4=7 L5=5 L6=0 blocked=5 test_failed=1.
Levels come only from the committed run artefacts recorded in reports/v3/experimental_proof.json; the queue in experiment_queue.md lists what is still blocked.

## Benchmark leakage

- splits_v3: by-source assignment; no source spans splits.
- duplicates quarantined as links (duplicates.jsonl), never deleted.
- vlun_overlap flags mark project/commit overlap with v1/v2.2 records for reviewer attention.
- flagged records: 6
