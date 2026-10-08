"""Authoritative audit-source registry for VLUN v2.2.

This module is the single source of truth for section 1 (mandatory source
index) and section 3 (source priority model) of the v2.2 audit-source
ingestion brief. It declares:

  * every mandatory archive (authoritative, secondary, research),
  * its source class S0-S5, its priority, and the ecosystems it covers,
  * the closed vocabularies the ingestion pipeline may use,
  * the normalisation maps for step 2 of the ingestion workflow,
  * validators for the section-4 ingestion record.

Nothing here touches the network and nothing here is ever rewritten by a
pipeline run. ``scripts/ingest_audit_sources.py`` reads this registry and
writes derived artefacts; ``scripts/validate.py`` re-imports the vocabularies
so a drift between registry and gate fails the build.

Governing rule (section 25): TRUTH > PROVENANCE > REPRODUCIBILITY >
DIVERSITY > SCALE > METRICS. An S1 audit finding is not a verified exploit
and an S4 dataset record is not a verified vulnerability; the class describes
provenance quality only.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DERIVED_V22 = ROOT / "derived_v2_2"
REPORTS = ROOT / "reports"
AUDIT_REPORT = REPORTS / "audit_source_ingestion_report.md"
AUDIT_JSON = REPORTS / "audit_source_ingestion.json"

# ---------------------------------------------------------------------------
# Section 3: source priority model. Class describes provenance quality only.
# ---------------------------------------------------------------------------

SOURCE_CLASSES = {
    "S0": "primary incident / official advisory / official disclosure",
    "S1": "professional security audit with verifiable scope",
    "S2": "public competitive audit / contest",
    "S3": "researcher public portfolio",
    "S4": "academic dataset / benchmark",
    "S5": "secondary aggregation / discovery source",
}

PRIORITIES = (
    "VERY_HIGH",
    "HIGH",
    "MEDIUM-HIGH",
    "MEDIUM",
    "RESEARCH / DISCOVERY",
    "RESEARCH / TAXONOMY",
    "RESEARCH / SOURCE DISCOVERY",
    "VERY_HIGH — DATASET QUALITY",
)

# ---------------------------------------------------------------------------
# Section 7: finding verification pipeline states and experiment levels.
# ---------------------------------------------------------------------------

VERIFICATION_STATES = (
    "UNVERIFIED",
    "RECONSTRUCTED",
    "COMPILES",
    "EXECUTES",
    "VIOLATION_REPRODUCED",
    "PATCH_VERIFIED",
    "REJECTED",
    "INCONCLUSIVE",
)

EXPERIMENT_LEVELS = tuple(f"L{i}" for i in range(7))

# L0 is prose only; L6 needs the same exploit to reproduce on the vulnerable
# revision and be blocked on the fixed revision. The mapping is stated once so
# the gate and the report cannot disagree about it.
LEVEL_TO_STATE = {
    "L0": "UNVERIFIED",
    "L1": "UNVERIFIED",
    "L2": "RECONSTRUCTED",
    "L3": "COMPILES",
    "L4": "EXECUTES",
    "L5": "VIOLATION_REPRODUCED",
    "L6": "PATCH_VERIFIED",
}

# ---------------------------------------------------------------------------
# Section 12: negative / hard-negative handling. A duplicate is real but
# already reported elsewhere; it must never contaminate the negative set.
# ---------------------------------------------------------------------------

NEGATIVE_CLASSES = (
    "VERIFIED_NON_EXPLOIT",
    "EXTERNALLY_REJECTED",
    "DUPLICATE",
    "ACCEPTED_RISK",
    "UNKNOWN",
)

# Section 8: severity is stored twice; the original is never overwritten.
SEVERITY_VOCAB = (
    "critical", "high", "medium", "low", "informational", "none", "unknown",
)

# Section 15: confidence is five separate dimensions, never collapsed early.
CONFIDENCE_DIMS = (
    "source_confidence",
    "code_provenance_confidence",
    "reproduction_confidence",
    "impact_confidence",
    "patch_confidence",
)

# Section 4: the mandatory ingestion record. Missing evidence is null/unknown,
# never fabricated.
REQUIRED_INGESTION_KEYS = (
    "source_name",
    "source_type",
    "source_priority",
    "source_url",
    "report_url",
    "report_hash",
    "auditor",
    "audit_date",
    "project",
    "protocol",
    "ecosystem",
    "language",
    "framework",
    "finding_id",
    "finding_title",
    "reported_severity",
    "repository_url",
    "audited_commit",
    "audited_tag",
    "scope",
    "fix_commit",
    "re_audit",
    "license",
    "redistribution_allowed",
    "candidate_status",
    "verification_status",
)

CANDIDATE_STATUS_VOCAB = (
    "candidate",
    "filtered_out",
    "admitted_corpus",
    "admitted_gold",
    "rejected",
    "unknown",
)

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
URL_RE = re.compile(r"^https?://", re.I)

# ---------------------------------------------------------------------------
# Section 1: mandatory source index. Every URL below is taken verbatim from
# the ingestion brief. `source_class` follows section 3; `priority` follows
# the brief's per-source label; `source_type` mirrors the brief's grouping.
# ---------------------------------------------------------------------------

MANDATORY_SOURCES: list[dict] = [
    {
        "source_name": "CoinFabrik",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "HIGH",
        "source_url": "https://www.coinfabrik.com/smart-contract-audit-reports/",
        "report_index_url": "https://github.com/CoinFabrik/coinfabrik-audit-reports",
        "auditor": "CoinFabrik",
        "ecosystems": ["evm", "substrate", "soroban", "stacks", "bitcoin"],
        "languages": ["solidity", "rust", "clarity"],
        "frameworks": ["evm", "substrate", "soroban"],
        "notes": "multi-language audit candidates; website archive + GitHub mirror",
    },
    {
        "source_name": "Hacken",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "VERY_HIGH",
        "source_url": "https://hacken.io/audits/reports/",
        "report_index_url": "https://hacken.io/audits/reports/",
        "companies_url": "https://hacken.io/audits/companies/",
        "api_docs_url": "https://docs.hacken.io/rest-apis/get-audits/",
        "auditor": "Hacken",
        "ecosystems": ["evm"],
        "languages": ["solidity"],
        "frameworks": ["evm"],
        "structured_api": True,
        "api_fields": ["audit name", "client/project", "audit date", "repository",
                       "commit", "scope", "assets audited", "platform", "language",
                       "finding ID", "severity", "finding title",
                       "remediation status", "audit type"],
        "notes": "use structured API for discovery where technically possible; "
                 "repository+commit are the highest-value fields for VLUN",
    },
    {
        "source_name": "Dedaub",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "VERY_HIGH",
        "source_url": "https://dedaub.com/smart-contract-audit/",
        "report_index_url": "https://dedaub.com/smart-contract-audit/",
        "auditor": "Dedaub",
        "ecosystems": ["evm", "defi"],
        "languages": ["solidity"],
        "frameworks": ["evm"],
        "notes": "EVM/DeFi/protocol-level/high-impact findings with strong "
                 "technical descriptions; map to public repos + exact revisions",
    },
    {
        "source_name": "Oak Security",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "VERY_HIGH",
        "source_url": "https://github.com/oak-security/audit-reports",
        "report_index_url": "https://github.com/oak-security/audit-reports",
        "auditor": "Oak Security",
        "ecosystems": ["evm", "cosmwasm", "cosmos-sdk", "neutron"],
        "languages": ["solidity", "rust"],
        "frameworks": ["evm", "cosmwasm", "cosmos-sdk"],
        "notes": "valuable for patch-oriented research; prioritise reports with "
                 "exact repo, commit/version, finding ids, remediation, re-audit",
    },
    {
        "source_name": "Softstack",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "HIGH",
        "source_url": "https://github.com/softstack/Smart-Contract-Security-Audits",
        "report_index_url": "https://github.com/softstack/Smart-Contract-Security-Audits",
        "auditor": "Softstack",
        "ecosystems": ["ethereum", "solana", "near", "cardano", "aptos", "sui",
                       "bnb-chain", "fantom", "eos", "tezos", "xrpl", "ton",
                       "fetch-ai"],
        "languages": ["solidity", "rust", "move"],
        "frameworks": ["evm", "anchor", "cosmwasm"],
        "notes": "multi-chain candidate discovery; every finding still needs "
                 "VLUN verification",
    },
    {
        "source_name": "Hashlock",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "VERY_HIGH",
        "source_url": "https://github.com/Hashlock-Auditing/hashlock-audits",
        "report_index_url": "https://github.com/Hashlock-Auditing/hashlock-audits",
        "auditor": "Hashlock",
        "ecosystems": ["evm", "solana", "substrate", "cosmwasm", "ibc", "xcm",
                       "aptos", "sui", "starknet", "near", "stacks", "cardano",
                       "algorand", "tezos", "tron", "icp"],
        "languages": ["solidity", "vyper", "rust", "move", "cairo", "clarity"],
        "frameworks": ["evm", "anchor", "substrate", "cosmwasm", "ibc", "xcm"],
        "notes": "primary driver for multi-language expansion; use aggressively "
                 "for ecosystem diversification",
    },
    {
        "source_name": "Auditware",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "HIGH",
        "source_url": "https://github.com/Auditware/audits",
        "report_index_url": "https://github.com/Auditware/audits",
        "auditor": "Auditware",
        "ecosystems": ["evm", "solana", "cosmwasm", "l1-sdk", "consensus",
                       "cross-chain"],
        "languages": ["solidity", "rust"],
        "frameworks": ["evm", "anchor", "cosmwasm"],
        "notes": "prioritise technically reproducible findings incl. L1/consensus "
                 "and cross-chain systems",
    },
    {
        "source_name": "QuillAudits",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "MEDIUM-HIGH",
        "source_url": "https://github.com/Quillhash/QuillAudit_Reports",
        "report_index_url": "https://github.com/Quillhash/QuillAudit_Reports",
        "auditor": "QuillAudits",
        "ecosystems": ["evm"],
        "languages": ["solidity"],
        "frameworks": ["evm"],
        "notes": "broad discovery; depths vary — never auto-admit, verify "
                 "important findings independently",
    },
    {
        "source_name": "HashEx",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "MEDIUM-HIGH",
        "source_url": "https://github.com/HashEx/public_audits",
        "report_index_url": "https://github.com/HashEx/public_audits",
        "auditor": "HashEx",
        "ecosystems": ["evm"],
        "languages": ["solidity"],
        "frameworks": ["evm"],
        "licensing_caution": True,
        "notes": "track copyright/licence per report; when redistribution is "
                 "unclear store metadata+URL+hash+ids+citations, never the full text",
    },
    {
        "source_name": "TechRate",
        "source_type": "authoritative_audit_archive",
        "source_class": "S1",
        "source_priority": "MEDIUM",
        "source_url": "https://github.com/TechRate/Smart-Contract-Audits",
        "report_index_url": "https://github.com/TechRate/Smart-Contract-Audits",
        "auditor": "TechRate",
        "ecosystems": ["evm"],
        "languages": ["solidity"],
        "frameworks": ["evm"],
        "notes": "historical discovery; many basic token audits — apply the "
                 "technical-relevance filter before any commit verification",
    },
    {
        "source_name": "0xRayaa",
        "source_type": "secondary_researcher_archive",
        "source_class": "S3",
        "source_priority": "MEDIUM-HIGH",
        "source_url": "https://github.com/0xRayaa/Audits",
        "report_index_url": "https://github.com/0xRayaa/Audits",
        "auditor": "0xRayaa (individual researcher)",
        "ecosystems": ["evm", "solana", "cosmwasm", "starknet"],
        "languages": ["solidity", "rust", "cairo"],
        "frameworks": ["evm", "anchor", "cosmwasm"],
        "notes": "secondary discovery incl. contests/bounties; researcher claims "
                 "are never automatically authoritative",
    },
    {
        "source_name": "Decentraland",
        "source_type": "secondary_historical_archive",
        "source_class": "S1",
        "source_priority": "HIGH",
        "source_url": "https://github.com/decentraland/smart-contract-audits",
        "report_index_url": "https://github.com/decentraland/smart-contract-audits",
        "auditor": "multiple (historical archive)",
        "ecosystems": ["evm"],
        "languages": ["solidity"],
        "frameworks": ["evm"],
        "longitudinal": True,
        "notes": "longitudinal research: implementation -> audit -> fix -> "
                 "re-audit; preserve all provenance, link equivalents, never "
                 "count re-reports as independent vulns",
    },
    {
        "source_name": "DIVE",
        "source_type": "research_dataset",
        "source_class": "S4",
        "source_priority": "RESEARCH / DISCOVERY",
        "source_url": "https://www.nature.com/articles/s41597-026-07025-5",
        "report_index_url": "https://www.nature.com/articles/s41597-026-07025-5",
        "auditor": None,
        "ecosystems": [],
        "languages": [],
        "frameworks": [],
        "notes": "taxonomy/coverage comparison and candidate discovery only; "
                 "never import directly into the verified subset",
    },
    {
        "source_name": "SCV-Tools-Benchmarks-Review",
        "source_type": "research_taxonomy",
        "source_class": "S4",
        "source_priority": "RESEARCH / TAXONOMY",
        "source_url": "https://www.sciencedirect.com/science/article/pii/S0164121226000221",
        "report_index_url": "https://www.sciencedirect.com/science/article/pii/S0164121226000221",
        "auditor": None,
        "ecosystems": [],
        "languages": [],
        "frameworks": [],
        "notes": "identify missing vulnerability classes, tools, benchmarks; "
                 "build the paper-class -> VLUN-class coverage matrix",
    },
    {
        "source_name": "Audit-Market-Dataset-Research",
        "source_type": "research_source_discovery",
        "source_class": "S4",
        "source_priority": "RESEARCH / SOURCE DISCOVERY",
        "source_url": "https://www.sciencedirect.com/science/article/pii/S0165410126000546",
        "report_index_url": "https://www.sciencedirect.com/science/article/pii/S0165410126000546",
        "auditor": None,
        "ecosystems": [],
        "languages": [],
        "frameworks": [],
        "notes": "source-discovery/methodology reference; track licence and "
                 "redistribution per described dataset",
    },
    {
        "source_name": "Dataset-Overlap-Research",
        "source_type": "research_dataset_quality",
        "source_class": "S4",
        "source_priority": "VERY_HIGH — DATASET QUALITY",
        "source_url": "https://www.sciencedirect.com/science/article/pii/S2405959526000238",
        "report_index_url": "https://www.sciencedirect.com/science/article/pii/S2405959526000238",
        "auditor": None,
        "ecosystems": [],
        "languages": [],
        "frameworks": [],
        "notes": "leakage prevention: duplicates, source/code overlap, "
                 "project/protocol/audit-report/temporal leakage",
    },
]

# Section 10: multi-language priority. Diversification is enforced against
# these targets, not against raw Solidity counts.
LANGUAGE_TARGETS = (
    "solidity", "vyper", "rust", "move", "cairo", "clarity",
)

ECOSYSTEM_TARGETS = (
    "evm", "solana", "cosmos", "substrate", "sui", "aptos", "starknet",
    "soroban", "stacks",
)

# Section 11: cross-language semantic mapping. Equivalent security properties
# in different ecosystems share a semantic_class but keep their own
# language-specific class; they are never stored as identical vulns.
SEMANTIC_CLASSES = (
    "authorization_bypass",
    "reentrancy",
    "integer_overflow",
    "access_control",
    "oracle_manipulation",
    "front_running",
    "denial_of_service",
    "logic_error",
    "cryptographic_failure",
    "implementation_specific",
)

SEVERITY_NORMALIZE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "none": "none",
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_severity(raw: str | None) -> tuple[str | None, str | None]:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None, raw
    key = raw.strip().lower()
    return SEVERITY_NORMALIZE.get(key, "unknown"), raw


def validate_ingestion_record(rec: dict) -> list[str]:
    """Section 4 record validation. Returns a list of failure strings."""
    out: list[str] = []
    for key in REQUIRED_INGESTION_KEYS:
        if key not in rec:
            out.append(f"missing key {key}")
    if rec.get("source_priority") not in PRIORITIES:
        out.append(f"source_priority {rec.get('source_priority')!r} not in vocabulary")
    if rec.get("source_type") not in (
        "authoritative_audit_archive", "secondary_researcher_archive",
        "secondary_historical_archive", "research_dataset", "research_taxonomy",
        "research_source_discovery", "research_dataset_quality",
    ):
        out.append(f"source_type {rec.get('source_type')!r} not in vocabulary")
    for url_key in ("source_url", "report_url", "repository_url"):
        val = rec.get(url_key)
        if val not in (None, "", "unknown") and isinstance(val, str) and val:
            if not URL_RE.match(val) and not val.startswith("file://"):
                out.append(f"{url_key} {val!r} is not http(s)")
    sha = rec.get("audited_commit")
    if sha not in (None, "", "unknown") and not SHA40_RE.match(str(sha)):
        out.append(f"audited_commit {sha!r} must be a full 40-hex sha or null/unknown")
    fix = rec.get("fix_commit")
    if fix not in (None, "", "unknown") and not SHA40_RE.match(str(fix)):
        out.append(f"fix_commit {fix!r} must be a full 40-hex sha or null/unknown")
    if rec.get("candidate_status") not in CANDIDATE_STATUS_VOCAB:
        out.append(f"candidate_status {rec.get('candidate_status')!r} not in vocabulary")
    if rec.get("verification_status") not in VERIFICATION_STATES:
        out.append(f"verification_status {rec.get('verification_status')!r} not in vocabulary")
    if rec.get("redistribution_allowed") not in (True, False, None):
        out.append("redistribution_allowed must be true/false/null")
    return out


def blank_ingestion_record(*, source: dict, report_url=None,
                           candidate_status: str = "candidate") -> dict:
    """A section-4 record with every finding-level field honestly empty.

    Used when a source is registered but no report has been parsed yet (for
    example: offline, paywalled, or not yet retrieved). Missing evidence is
    null/unknown per section 24 — never guessed.
    """
    return {
        "source_name": source["source_name"],
        "source_type": source["source_type"],
        "source_priority": source["source_priority"],
        "source_url": source["source_url"],
        "report_url": report_url,
        "report_hash": None,
        "auditor": source.get("auditor"),
        "audit_date": None,
        "project": None,
        "protocol": None,
        "ecosystem": None,
        "language": None,
        "framework": None,
        "finding_id": None,
        "finding_title": None,
        "reported_severity": None,
        "repository_url": None,
        "audited_commit": None,
        "audited_tag": None,
        "scope": None,
        "fix_commit": None,
        "re_audit": None,
        "license": None,
        "redistribution_allowed": None,
        "candidate_status": candidate_status,
        "verification_status": "UNVERIFIED",
    }


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{lineno} invalid JSON: {exc}") from exc
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    tmp.replace(path)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    tmp.replace(path)
