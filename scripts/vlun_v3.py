"""Shared constants and helpers for the VLUN V3 layer (18 new sources).

The V3 layer is ADDITIVE: it never rewrites ``jsonl/``, ``jsonl_ml/``,
``derived/`` or ``derived_v2_2/``. New artefacts live under::

    jsonl_v3/     source layer (one row per harvested candidate pointer)
    derived_v3/   normalized records, ledgers, manifest
    splits_v3/    by-source splits (no source ever spans splits)
    benchmark/    v3_R_*.jsonl + v3_S_*.jsonl + v3_manifest.json (new families only)
    reports/v3/   quality / integration / experiment-queue reports

Governing rule: TRUTH > PROVENANCE > REPRODUCIBILITY > PATCH VERIFICATION >
COVERAGE > SCALE. Fields that cannot be established from the cloned material
are the string ``"unknown"`` or ``None`` -- never guessed.

Verification discipline for this pass: no exploit is executed here, so no
record may exceed L1 (published PoC). L2-L6 require run artefacts that do not
exist yet; the experiment queue in reports/v3/ lists what would produce them.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
V3_DIR = ROOT / "V3"
CLONES = V3_DIR / "clones"
JSONL_V3 = ROOT / "jsonl_v3"
DERIVED_V3 = ROOT / "derived_v3"
SPLITS_V3 = ROOT / "splits_v3"
REPORTS_V3 = ROOT / "reports" / "v3"
BENCH = ROOT / "benchmark"

DATASET_VERSION_V3 = "3.0"
SCHEMA_VERSION_V3 = "3.0"

UNKNOWN = "unknown"

# Verification levels (same ladder as the VLUN model). This pass assigns only
# L0/L1: higher levels need run artefacts produced by actual execution.
VERIFICATION_LEVELS = ("L0", "L1", "L2", "L3", "L4", "L5", "L6")

# Candidate decisions (closed vocabulary).
DECISIONS = (
    "IMPORT",
    "IMPORT_AS_UNVERIFIED",
    "IMPORT_AS_NEGATIVE",
    "CORROBORATION_ONLY",
    "REJECT",
    "RESEARCH_ONLY",
)

# Records admitted to derived_v3/records.jsonl (the shippable normalized set).
ADMITTED_DECISIONS = ("IMPORT", "IMPORT_AS_UNVERIFIED", "IMPORT_AS_NEGATIVE")

# Negative taxonomy (closed vocabulary -- never collapse to "false_positive").
NEGATIVE_CLASSES = (
    "verified_non_exploit",
    "externally_rejected",
    "duplicate",
    "out_of_scope",
    "unknown",
)

# Commit confidence (closed vocabulary -- inferred is never upgraded to exact).
COMMIT_CONFIDENCE = ("exact", "strong", "inferred", "unknown")

SHA40_RE = re.compile(r"\b[0-9a-f]{40}\b")
SHA7_40_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
DATE_RE = re.compile(r"\b(20\d\d)-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")
GITHUB_REPO_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")

# ---------------------------------------------------------------------------
# Source registry. `clone` is the directory under V3/clones. Licence posture is
# METADATA_ONLY for every third-party source: VLUN keeps link + sha256 +
# attributed facts, never redistributed report text (see per-source notes).
# `tier` follows the VLUN 0-4 classification. Scores/priorities are carried over
# from the V3 research dossiers (V3/01_ranked_table.md, 02_source_dossiers.md).
# ---------------------------------------------------------------------------

SOURCES_V3: tuple[dict, ...] = (
    dict(source_id="zellic-publications", source_name="Zellic publications",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/Zellic/publications",
         organization="Zellic", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["solana", "sui", "aptos", "evm", "stellar"],
         languages=["rust", "move", "solidity"],
         time_range="unknown", provenance_quality=92, ground_truth="G5",
         priority="P0", score=92, clone="zellic-publications"),
    dict(source_id="pashov-audits", source_name="Pashov Audit Group",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/pashov/audits",
         organization="Pashov Audit Group", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="unknown", provenance_quality=86, ground_truth="G5",
         priority="P0", score=86, clone="pashov-audits"),
    dict(source_id="nethermind-audits", source_name="Nethermind Security",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/NethermindEth/PublicAuditReports",
         organization="Nethermind", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm", "starknet"], languages=["solidity", "cairo", "rust"],
         time_range="unknown", provenance_quality=85, ground_truth="G5",
         priority="P0", score=85, clone="nethermind-audits"),
    dict(source_id="certora-reports", source_name="Certora SecurityReports",
         source_type="professional_audit_formal_verification", tier=1,
         first_party=True,
         canonical_url="https://github.com/Certora/SecurityReports",
         organization="Certora", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm", "solana", "stellar", "sui"],
         languages=["solidity", "vyper", "rust", "move"],
         time_range="unknown", provenance_quality=85, ground_truth="G5",
         priority="P0", score=85, clone="certora-reports"),
    dict(source_id="hexens-reports", source_name="Hexens public reports",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/Hexens/Smart-Contract-Review-Public-Reports",
         organization="Hexens", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm", "fuel", "solana"], languages=["solidity", "sway", "rust"],
         time_range="unknown", provenance_quality=86, ground_truth="G5",
         priority="P0", score=86, clone="hexens-reports"),
    dict(source_id="defihacklabs", source_name="DeFiHackLabs",
         source_type="incident_database", tier=0, first_party=False,
         canonical_url="https://github.com/SunWeb3Sec/DeFiHackLabs",
         organization="SunWeb3Sec (third-party incident reproduction)",
         license="unknown", redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="unknown", provenance_quality=78, ground_truth="G5",
         priority="P0", score=78, clone="defihacklabs"),
    dict(source_id="informal-audits", source_name="Informal Systems audits",
         source_type="professional_audit_formal_verification", tier=1,
         first_party=True,
         canonical_url="https://github.com/informalsystems/audits",
         organization="Informal Systems", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["cosmos", "ibc"], languages=["rust", "go"],
         time_range="unknown", provenance_quality=81, ground_truth="G4",
         priority="P0", score=81, clone="informal-audits"),
    dict(source_id="cyba-audits", source_name="Cyba Blockchain Security",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/cybasecurity/audits",
         organization="Cyba Blockchain Security", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["stacks", "evm"], languages=["clarity", "solidity"],
         time_range="unknown", provenance_quality=81, ground_truth="G4",
         priority="P0", score=81, clone="cyba-audits"),
    dict(source_id="abdk-audits", source_name="ABDK Consulting",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/abdk-consulting/audits",
         organization="ABDK Consulting", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm", "zk"], languages=["solidity"],
         time_range="unknown", provenance_quality=75, ground_truth="G4",
         priority="P1", score=75, clone="abdk-audits"),
    dict(source_id="sigmaprime-audits", source_name="Sigma Prime",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/sigp/public-audits",
         organization="Sigma Prime", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["ethereum-infra", "evm", "l2"],
         languages=["rust", "go", "solidity"],
         time_range="unknown", provenance_quality=72, ground_truth="G4",
         priority="P1", score=72, clone="sigmaprime-audits"),
    dict(source_id="ackee-audits", source_name="Ackee Blockchain",
         source_type="professional_audit", tier=1, first_party=True,
         canonical_url="https://github.com/Ackee-Blockchain/public-audit-reports",
         organization="Ackee Blockchain", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="unknown", provenance_quality=77, ground_truth="G5",
         priority="P1", score=77, clone="ackee-audits"),
    dict(source_id="anza-security-audits", source_name="Anza security audits (aggregator)",
         source_type="professional_audit_mirror", tier=1, first_party=False,
         canonical_url="https://github.com/anza-xyz/security-audits",
         organization="Anza (aggregator; reports authored by Halborn, OtterSec, Neodyme, Zellic, Trail of Bits, NCC, Certora, Least Authority, ZKSecurity, Qedit, Asymmetric, Code4rena)",
         license="unknown", redistribution="METADATA_ONLY",
         ecosystems=["solana"], languages=["rust"],
         time_range="unknown", provenance_quality=60, ground_truth="G0-pointer",
         priority="P2", score=60, clone="anza-security-audits",
         notes="Pointer/mirror layer: every record carries mirror_of handling; "
               "the auditor original remains the canonical source."),
    dict(source_id="smartbugs-curated", source_name="SmartBugs Curated",
         source_type="research_dataset", tier=4, first_party=False,
         canonical_url="https://github.com/smartbugs/smartbugs-curated",
         organization="SmartBugs (ASE-2020 paper lineage)", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="unknown", provenance_quality=46, ground_truth="G2-max",
         priority="P2-research", score=46, clone="smartbugs-curated",
         notes="Taxonomy / benchmark-design reference only; never ground truth."),
    dict(source_id="c4-renzo-findings", source_name="Code4rena 2024-04 Renzo",
         source_type="competitive_audit", tier=2, first_party=True,
         canonical_url="https://github.com/code-423n4/2024-04-renzo-findings",
         organization="Code4rena", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="2024-04/2024-06", provenance_quality=91,
         ground_truth="G5", priority="P0", score=91,
         clone="c4-renzo-findings"),
    dict(source_id="c4-phi-findings", source_name="Code4rena 2024-08 Phi",
         source_type="competitive_audit", tier=2, first_party=True,
         canonical_url="https://github.com/code-423n4/2024-08-phi-findings",
         organization="Code4rena", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="2024-08/2024-10", provenance_quality=91,
         ground_truth="G5", priority="P0", score=91,
         clone="c4-phi-findings"),
    dict(source_id="c4-reserve-findings", source_name="Code4rena 2024-07 Reserve",
         source_type="competitive_audit", tier=2, first_party=True,
         canonical_url="https://github.com/code-423n4/2024-07-reserve-findings",
         organization="Code4rena", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="2024-07/2024-10", provenance_quality=91,
         ground_truth="G5", priority="P0", score=91,
         clone="c4-reserve-findings"),
    dict(source_id="sherlock-symmetrical",
         source_name="Sherlock 2024-06 Symmetrical",
         source_type="competitive_audit", tier=2, first_party=True,
         canonical_url="https://github.com/sherlock-audit/2024-06-symmetrical-update-2-judging",
         organization="Sherlock", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="2024-06", provenance_quality=87, ground_truth="G5",
         priority="P0-after-C4", score=87, clone="sherlock-symmetrical"),
    dict(source_id="sherlock-optimism",
         source_name="Sherlock 2023-01 Optimism",
         source_type="competitive_audit", tier=2, first_party=True,
         canonical_url="https://github.com/sherlock-audit/2023-01-optimism-judging",
         organization="Sherlock", license="unknown",
         redistribution="METADATA_ONLY",
         ecosystems=["evm"], languages=["solidity"],
         time_range="2023-01", provenance_quality=87, ground_truth="G5",
         priority="P0-after-C4", score=87, clone="sherlock-optimism"),
)

SOURCE_IDS = tuple(s["source_id"] for s in SOURCES_V3)

# Projects with dossier-established multi-auditor coverage (independent
# confirmation signal; used only for scoring, never asserted per finding).
MULTI_AUDITOR_PROJECTS = {
    "spl-token-2022", "spl token 2022", "token-2022",
    "granite", "lido", "aave", "risc zero", "risc0", "risc-zero",
    "1inch", "uniswap", "penpie", "curve", "euler", "telcoin",
}

# DASP (SmartBugs) category -> VLUN normalized class. The original DASP label is
# always preserved in `original_vulnerability_class`.
DASP_TO_VLUN = {
    "access_control": "Access Control",
    "arithmetic": "Arithmetic",
    "bad_randomness": "Randomness",
    "denial_of_service": "Denial of Service",
    "front_running": "Front-running",
    "other": "Other",
    "reentrancy": "Reentrancy",
    "short_addresses": "Short Address",
    "time_manipulation": "Time Manipulation",
    "unchecked_low_level_calls": "Unchecked Low-Level Call",
}

C4_RISK_TO_SEVERITY = {
    "3": "High",
    "2": "Medium",
    "Q": "Low",
    "G": "Informational",
}

# Zellic README Network column -> (language, ecosystem). Only values observed
# in the README table are mapped; anything else stays unknown.
ZELLIC_NETWORK_MAP = {
    "solana": ("rust", "solana"),
    "evm": ("solidity", "evm"),
    "sui": ("move", "sui"),
    "aptos": ("move", "aptos"),
    "move": ("move", UNKNOWN),
    "stellar": ("rust", "stellar"),
    "rust": ("rust", UNKNOWN),
    "ton": (UNKNOWN, "ton"),
    "bitcoin": (UNKNOWN, "bitcoin"),
}

# Certora README Platform column -> (language, ecosystem).
CERTORA_PLATFORM_MAP = {
    "evm": ("solidity", "evm"),
    "solana": ("rust", "solana"),
    "sui": ("move", "sui"),
    "stellar": ("rust", "stellar"),
    "soroban": ("rust", "stellar"),
    "aptos": ("move", "aptos"),
    "starknet": ("cairo", "starknet"),
}

# --- io helpers ------------------------------------------------------------


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n": without it Windows text mode emits CRLF, making build
    # output platform-dependent. Committed files are LF (.gitattributes).
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, obj: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n": see write_jsonl — platform-stable LF output.
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clone_head(clone_dir: Path) -> str:
    """HEAD SHA of a V3 clone, or "unknown" (shallow clones have no history)."""
    try:
        out = subprocess.run(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30)
        sha = out.stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            return sha
    except Exception:
        pass
    return UNKNOWN


def log(msg: str) -> None:
    print(msg, flush=True)


def norm_title(title: str) -> str:
    return re.sub(r"\s+", " ", (title or "").strip().lower())


# --- quality scoring (spec section 26 weights; max 95 as specified) ----------


def quality_score(signals: dict) -> tuple[int, dict]:
    """Deterministic 0-95 score from observed signals only.

    signals keys: tier, first_party, has_repo, has_commit40, specificity
    (0-3), poc (0-3: 0 none, 1 mentioned, 2 section+code, 3 executable file),
    patch (0-2: 0 none, 1 described, 2 exact commit), multi_auditor (bool),
    non_evm (bool), negative (0-2: 0 positive, 1 corroboration, 2 hard negative).
    """
    parts: dict[str, int] = {}
    tier = signals.get("tier", 4)
    fp = signals.get("first_party", False)
    if tier <= 0:
        parts["primary_provenance"] = 12
    elif tier == 1 and fp:
        parts["primary_provenance"] = 15
    elif tier == 1:
        parts["primary_provenance"] = 12
    elif tier == 2 and signals.get("judged", False):
        parts["primary_provenance"] = 10
    elif tier == 2:
        parts["primary_provenance"] = 6
    elif tier == 3:
        parts["primary_provenance"] = 5
    else:
        parts["primary_provenance"] = 3

    if signals.get("has_repo") and signals.get("has_commit40"):
        parts["exact_repository_commit"] = 15
    elif signals.get("has_repo") or signals.get("has_commit40"):
        parts["exact_repository_commit"] = 8
    elif signals.get("scope_evidence"):
        parts["exact_repository_commit"] = 5
    else:
        parts["exact_repository_commit"] = 0

    parts["technical_specificity"] = {0: 2, 1: 4, 2: 7, 3: 10}.get(
        signals.get("specificity", 0), 0)
    parts["poc_quality"] = {0: 0, 1: 4, 2: 8, 3: 12}.get(signals.get("poc", 0), 0)
    # Nothing is executed in this integration pass: reproducibility is 0 for
    # every record, stated explicitly rather than hidden.
    parts["reproducibility"] = 0
    parts["patch_evidence"] = {0: 0, 1: 5, 2: 10}.get(signals.get("patch", 0), 0)
    parts["independent_confirmation"] = 5 if signals.get("multi_auditor") else 0
    parts["ecosystem_diversity"] = 5 if signals.get("non_evm") else 2
    parts["negative_value"] = {0: 0, 1: 3, 2: 5}.get(signals.get("negative", 0), 0)
    return sum(parts.values()), parts
