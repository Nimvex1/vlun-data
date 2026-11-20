"""Build wave1/00_governance/ (PRESENT sentinel, rights, source registry).

Stdlib only, idempotent, single-writer confined to wave1/.
"""
from __future__ import annotations

import json
from pathlib import Path

from _common import ROOT, WAVE1, guard_wave1, sha256_file, write_json, write_jsonl, utc_now

PRESENT_TARGETS = [
    "README.md",
    "benchmark/manifest.json",
    "derived_v3/manifest.json",
    "pyproject.toml",
    "scripts/vlun_v3.py",
    "Vbeta/present_snapshot.json",
    "docs/SOURCE_CANDIDATES.md",
    "jsonl/patches.jsonl",
]

RIGHTS = [
    {
        "source_id": "evmbench",
        "decision": "DROPPED",
        "license": "Apache-2.0",
        "reason": "PARENT GOVERNANCE #1: fix patches are synthetic overlays against a frozen "
                  "evmbench-org mirror, not upstream fixing commits of the real repository; "
                  "ineligible for VLUN-Prove or G/J. See derived_prove/candidate_ledger.jsonl:45-46.",
        "data_handling": "NONE",
    },
    {
        "source_id": "reevmbench",
        "decision": "APPROVED_IN_SCOPE",
        "license": "Apache-2.0",
        "reason": "PARENT GOVERNANCE #2: the docs/SOURCE_CANDIDATES.md exclusion targeted "
                  "blocksecteam/audit-reports (unlicensed prose reports). ReEVMBench is a distinct "
                  "Apache-2.0 executable Anvil-harness repository; real on-chain incidents with "
                  "verifiable provenance. Not synthetic/educational.",
        "data_handling": "METADATA_ONLY + executable harness facts (no prose redistribution)",
    },
    {
        "source_id": "c4_mitigation",
        "decision": "APPROVED",
        "license": "CC-BY-4.0-attribution",
        "reason": "Judge verdicts and sponsor fix commits are attributed facts; record "
                  "permalink + verdict classification, not full issue prose.",
        "data_handling": "METADATA_ONLY (verdict class, commits, permalink, sha256)",
    },
    {
        "source_id": "judge_negatives",
        "decision": "APPROVED_CONDITIONAL",
        "license": "METADATA_ONLY",
        "reason": "PARENT GOVERNANCE #3: 6-axis structured rejection evidence + duplicate pairs "
                  "+ target AST facts + permalink/comment_sha256. Full comment prose is NEVER vendored.",
        "data_handling": "METADATA_ONLY (6 axes, no prose)",
    },
    {
        "source_id": "formal_specs",
        "decision": "APPROVED_CONDITIONAL",
        "license": "unverified-per-repo",
        "reason": "Recon-Fuzz/audits, Certora/gho-competition, "
                  "Certora/uniswap-v4-periphery-cantina-fv: machine-checked invariant properties "
                  "are facts; redistribution rights must be checked per repo before any prose copy.",
        "data_handling": "METADATA_ONLY (rule id, property, commit, verdict)",
    },
    {
        "source_id": "markdown_two_revision",
        "decision": "APPROVED_CONDITIONAL",
        "license": "unverified-per-repo",
        "reason": "asymmetric-research/security-advisories, mixbytes/audits_public, yAudit: "
                  "resolve 40-hex 'Fixed in commit' SHAs to real commits; record pointer + hash, "
                  "no report prose. Dedup against Vbeta's 11 mixbytes stubs / 267 Solodit URLs.",
        "data_handling": "METADATA_ONLY (pointer + commit + sha256)",
    },
    {
        "source_id": "ghsa_web3_netnew",
        "decision": "APPROVED",
        "license": "CC-BY-4.0",
        "reason": "github/advisory-database is CC-BY-4.0. Only net-new repos: "
                  "OpenZeppelin/openzeppelin-contracts, Vectorized/solady, CosmWasm/cosmwasm, "
                  "cosmos/cosmos-sdk. vyperlang/vyper SKIPPED (49 GHSA / 43 CVE already in v2.2).",
        "data_handling": "METADATA_ONLY (GHSA id, CVE, fix commit, version range)",
    },
]

SOURCES = [
    {
        "source_id": "c4_mitigation",
        "status": "ACTIVE",
        "repos": [
            "code-423n4/2023-05-asymmetry-mitigation-findings",
            "code-423n4/2023-07-angle-mitigation-findings",
            "code-423n4/2023-08-pooltogether-mitigation-findings",
            "code-423n4/2023-09-goodentry-mitigation-findings",
            "code-423n4/2023-10-asymmetry-mitigation-findings",
            "code-423n4/2024-02-renft-mitigation-findings",
            "code-423n4/2024-03-saltyio-mitigation-findings",
            "code-423n4/2024-04-ai-arena-mitigation-findings",
            "code-423n4/2024-05-gondi-mitigation-findings",
            "code-423n4/2024-06-renzo-mitigation-findings",
            "code-423n4/2024-09-reserve-mitigation-findings",
        ],
        "dedup_key": "(normalized_repo_slug, finding_id)",
        "bridge_key": "(original_repo, original_finding_id)",
    },
    {
        "source_id": "formal_specs",
        "status": "ACTIVE",
        "repos": [
            "Recon-Fuzz/audits",
            "Certora/gho-competition",
            "Certora/uniswap-v4-periphery-cantina-fv",
        ],
        "dedup_key": "(repo_slug, spec_id, invariant_id)",
        "exclusion": "200 certora-reports:* keys already in jsonl_v3/findings.jsonl",
    },
    {
        "source_id": "markdown_two_revision",
        "status": "ACTIVE",
        "repos": [
            "asymmetric-research/security-advisories",
            "mixbytes/audits_public",
        ],
        "yaudit_note": "yAudit reports addressed by content URL (no single canonical repo)",
        "dedup_key": "sha256(norm_firm|norm_protocol|full_fix_sha)",
    },
    {
        "source_id": "ghsa_web3_netnew",
        "status": "ACTIVE",
        "repos": [
            "OpenZeppelin/openzeppelin-contracts",
            "Vectorized/solady",
            "CosmWasm/cosmwasm",
            "cosmos/cosmos-sdk",
        ],
        "skip": ["vyperlang/vyper"],
        "dedup_key": "GHSA_id",
    },
    {
        "source_id": "reevmbench",
        "status": "QUEUED",
        "repos": ["blocksecteam/ReEVMBench"],
        "dedup_key": "tx:<chain>:<lowercase-0x64>",
    },
    {
        "source_id": "evmbench",
        "status": "DROPPED",
        "repos": [],
        "reason": "PARENT GOVERNANCE #1",
    },
]


def main() -> None:
    # 1) PRESENT sentinel: hash canonical files BEFORE any wave1 work.
    sentinel = {
        "note": "wave1 PRESENT sentinel. Canonical hashes are read-only copies of the "
                "baseline; wave1 writers never edit these files. Own hash covers wave1 scripts.",
        "created_at": utc_now(),
        "canonical_sha256": {},
        "missing": [],
    }
    for rel in PRESENT_TARGETS:
        p = ROOT / rel
        if p.exists():
            sentinel["canonical_sha256"][rel] = sha256_file(p)
        else:
            sentinel["missing"].append(rel)
    scripts = sorted((WAVE1 / "scripts").glob("*.py"))
    scripts += sorted((WAVE1 / "scripts" / "adapters").glob("*.py"))
    sentinel["wave1_script_sha256"] = {
        str(p.relative_to(WAVE1)).replace("\\", "/"): sha256_file(p) for p in scripts if p.is_file()
    }
    # self-hash computed over the canonical hashes only (stable across runs)
    sentinel["self_sha256"] = __import__("hashlib").sha256(
        json.dumps(sentinel["canonical_sha256"], sort_keys=True).encode()
    ).hexdigest()

    write_json(guard_wave1(WAVE1 / "00_governance" / "PRESENT.md.json"), sentinel)
    md = [
        "# wave1 PRESENT sentinel",
        "",
        f"Canonical baseline hash: `{sentinel['self_sha256']}`",
        "",
        "This sentinel is NEW and lives only under `wave1/`. The canonical sentinel",
        "`Vbeta/present_snapshot.json` is read-only and must not be edited.",
        "",
        "| canonical path | sha256 |",
        "|---|---|",
    ]
    for rel, h in sorted(sentinel["canonical_sha256"].items()):
        md.append(f"| `{rel}` | `{h}` |")
    md += ["", "## wave1 scripts", "", "| script | sha256 |", "|---|---|"]
    for rel, h in sorted(sentinel.get("wave1_script_sha256", {}).items()):
        md.append(f"| `{rel}` | `{h}` |")
    md.append("")
    p = guard_wave1(WAVE1 / "00_governance" / "PRESENT.md")
    p.write_text("\n".join(md), encoding="utf-8", newline="\n")

    write_jsonl(WAVE1 / "00_governance" / "rights.jsonl", RIGHTS)
    write_jsonl(WAVE1 / "00_governance" / "source_registry.jsonl", SOURCES)
    print(f"[governance] canonical files hashed: {len(sentinel['canonical_sha256'])}")
    print(f"[governance] missing files: {sentinel['missing']}")
    print(f"[governance] rights rows: {len(RIGHTS)}; source rows: {len(SOURCES)}")


if __name__ == "__main__":
    main()
