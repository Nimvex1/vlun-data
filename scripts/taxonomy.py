#!/usr/bin/env python3
"""P7: normalise v1's C4 class strings into a four-level taxonomy.

v1's `vulnerability_classes` are already slashes (`DeFi/oracle manipulation`),
so the hierarchy exists but is two levels deep, inconsistently named, and has
trailing whitespace in some category names. This maps them onto

    category -> family -> class -> subtype

and records which rule fired, so a label can always be traced to the v1 string
that produced it. The original C4 string is kept untouched in
`taxonomy.c4_original`; nothing is overwritten.

Labels are only assigned when the v1 class supports them. A record whose class
is unknown stays unknown rather than being forced into the nearest bucket.
"""

from __future__ import annotations

import re

TOP_LEVEL = (
    "Access Control", "Accounting", "DeFi", "Cross-Contract", "Cross-Chain",
    "Cryptography / Signatures", "Denial of Service", "Governance", "Logic Error",
    "Oracle", "Reentrancy / External Calls", "Token Standards", "Upgradeability",
    "Unknown",
)

# C4 category label -> canonical top-level
CATEGORY_MAP = {
    "access control": "Access Control",
    "accounting": "Accounting",
    "accounting / financial logic": "Accounting",
    "defi": "DeFi",
    "cross-contract": "Cross-Contract",
    "cross-contract / protocol architecture": "Cross-Contract",
    "cross-chain": "Cross-Chain",
    "cross-chain / bridge": "Cross-Chain",
    "signatures": "Cryptography / Signatures",
    "signatures / cryptography": "Cryptography / Signatures",
    "denial of service": "Denial of Service",
    "governance": "Governance",
    "governance/governance": "Governance",
    "logic error": "Logic Error",
    "reentrancy": "Reentrancy / External Calls",
    "reentrancy / external calls": "Reentrancy / External Calls",
    "token": "Token Standards",
    "token / erc standards": "Token Standards",
    "upgradeability": "Upgradeability",
    "oracle": "Oracle",
}

# (top-level, family, class) keyed on the normalised C4 class string.
# Only entries whose *class* is directly attested by the v1 string appear here;
# `subtype` is filled from the same string, never guessed from the title.
KNOWN = {
    "de fi/oracle manipulation": ("DeFi", "Price Sources", "Oracle manipulation", "Single-source oracle dependence"),
    "defi/oracle manipulation": ("DeFi", "Price Sources", "Oracle manipulation", "Single-source oracle dependence"),
    "de fi/stale oracle": ("DeFi", "Price Sources", "Stale price", "Missing staleness or heartbeat check"),
    "defi/stale oracle": ("DeFi", "Price Sources", "Stale price", "Missing staleness or heartbeat check"),
    "oracle/stale oracle": ("Oracle", "Price Sources", "Stale price", "Missing staleness or heartbeat check"),
    "defi/slippage failure": ("DeFi", "Pricing", "Slippage", "Unbounded or user-absent slippage bound"),
    "defi/amm logic": ("DeFi", "AMM", "AMM invariant logic", "Price or invariant arithmetic"),
    "defi/leverage": ("DeFi", "Position Management", "Leverage accounting", "Position or leverage bound miscalculation"),
    "defi/rewards/points accounting": ("DeFi", "Incentives", "Reward accounting", "Points or rewards accrual"),
    "defi/flash-loan interaction": ("DeFi", "Atomicity", "Flash-loan interaction", "Same-transaction composition"),
    "defi/insolvency": ("DeFi", "Solvency", "Bad solvency", "Liabilities exceed recoverable assets"),
    "defi/bad debt": ("DeFi", "Solvency", "Bad debt", "Unrecoverable credit"),
    "defi/liquidation failure": ("DeFi", "Liquidation", "Liquidation failure", "Liquidation blocked or mispriced"),
    "denial of service/blocked withdrawals": ("Denial of Service", "Availability of User Funds", "Blocked withdrawals", None),
    "denial of service/permanent dos": ("Denial of Service", "Permanent", "Permanent DoS", None),
    "denial of service/temporary dos": ("Denial of Service", "Temporary", "Temporary DoS", None),
    "denial of service/griefing": ("Denial of Service", "Griefing", "Griefing", None),
    "denial of service/gas exhaustion": ("Denial of Service", "Resource Exhaustion", "Gas exhaustion", None),
    "denial of service/unbounded iteration": ("Denial of Service", "Resource Exhaustion", "Unbounded iteration", None),
    "denial of service/blocked liquidation": ("Denial of Service", "Availability of User Funds", "Blocked liquidation", None),
    "reentrancy / external calls/callback abuse": ("Reentrancy / External Calls", "Reentrancy", "Callback abuse", None),
    "reentrancy / external calls/unvalidated return value": ("Reentrancy / External Calls", "External Calls", "Unvalidated return value", None),
    "accounting / financial logic/share inflation": ("Accounting", "Share Accounting", "Inflation", "Donation-based inflation"),
    "accounting / financial logic/reserve accounting": ("Accounting", "Reserve Accounting", "Incorrect reserves", None),
    "accounting / financial logic/incorrect balance accounting": ("Accounting", "Balance Accounting", "Incorrect balance accounting", None),
    "accounting / financial logic/collateral accounting": ("Accounting", "Collateral Accounting", "Incorrect collateral accounting", None),
    "accounting / financial logic/asset/share mismatch": ("Accounting", "Share Accounting", "Asset/share mismatch", "First-depositor donation"),
    "accounting / financial logic/rounding error": ("Accounting", "Arithmetic", "Rounding error", None),
    "accounting / financial logic/fee miscalculation": ("Accounting", "Arithmetic", "Fee miscalculation", None),
    "accounting / financial logic/debt accounting": ("Accounting", "Debt Accounting", "Incorrect debt accounting", None),
    "token / erc standards/erc4626": ("Token Standards", "Vault Standard", "ERC4626 non-compliance", None),
    "token / erc standards/erc721": ("Token Standards", "NFT Standard", "ERC721 assumption break", None),
    "token / erc standards/erc1155": ("Token Standards", "NFT Standard", "ERC1155 assumption break", None),
    "token / erc standards/approval misuse": ("Token Standards", "Approvals", "Approval misuse", None),
    "token / erc standards/erc20 assumptions": ("Token Standards", "ERC20", "Non-standard ERC20 assumption", "Fee-on-transfer or rebasing token"),
    "token / erc standards/rebasing": ("Token Standards", "ERC20", "Rebasing token mishandling", None),
    "token / erc standards/token callback": ("Token Standards", "Callbacks", "Token callback", "ERC777 / ERC1363 hook"),
    "signatures / cryptography/incorrect hashing": ("Cryptography / Signatures", "Hashing", "Incorrect hash construction", None),
    "signatures / cryptography/authorization-by-signature bugs": ("Cryptography / Signatures", "Authorisation", "Authorisation signature bug", None),
    "signatures / cryptography/replay": ("Cryptography / Signatures", "Replay", "Signature replay", None),
    "signatures / cryptography/incorrect nonce handling": ("Cryptography / Signatures", "Replay", "Incorrect nonce handling", None),
    "signatures / cryptography/missing domain separation": ("Cryptography / Signatures", "Domain Separation", "Missing domain separation", None),
    "signatures / cryptography/signature malleability": ("Cryptography / Signatures", "Encoding", "Signature malleability", None),
    "cross-contract / protocol architecture/broken invariant": ("Cross-Contract", "Cross-Contract Invariant", "Broken cross-contract invariant", None),
    "cross-contract / protocol architecture/inconsistent state": ("Cross-Contract", "State Consistency", "Inconsistent cross-contract state", None),
    "cross-contract / protocol architecture/incompatible assumptions": ("Cross-Contract", "Assumptions", "Incompatible protocol assumptions", None),
    "cross-contract / protocol architecture/trust-boundary failure": ("Cross-Contract", "Trust Boundaries", "Trust-boundary failure", None),
    "cross-contract / protocol architecture/unsafe composability": ("Cross-Contract", "Composability", "Unsafe composability", None),
    "cross-chain / bridge/bridge authorization": ("Cross-Chain", "Bridge Authorisation", "Bridge authorisation", None),
    "cross-chain / bridge/message verification": ("Cross-Chain", "Message Verification", "Message verification", None),
    "cross-chain / bridge/chain-id mismatch": ("Cross-Chain", "Domain Separation", "chainId mismatch", None),
    "cross-chain / bridge/replay": ("Cross-Chain", "Replay", "Cross-domain replay", None),
    "cross-chain / bridge/accounting mismatch": ("Cross-Chain", "Accounting", "Cross-chain accounting mismatch", None),
    "governance/emergency controls": ("Governance", "Emergency Controls", "Emergency control weakness", None),
    "governance/governance / timelock": ("Governance", "Timelock", "Timelock bypass", None),
    "logic error/wrong variable / branch": ("Logic Error", "Branch Selection", "Wrong variable or branch", None),
    "logic error/missing state update": ("Logic Error", "State Update", "Missing state update", None),
    "upgradeability/unsafe delegatecall": ("Upgradeability", "Proxy", "Unsafe delegatecall", None),
    "upgradeability/upgrade authorization": ("Upgradeability", "Upgrade Authorisation", "Unauthorised upgrade", None),
    "upgradeability/proxy initialization": ("Upgradeability", "Initialisation", "Uninitialised proxy", None),
    "upgradeability/storage collision": ("Upgradeability", "Storage Layout", "Storage collision", None),
    "access control/missing revocation / kill switch": ("Access Control", "Emergency Controls", "Missing kill switch", None),
    "access control/missing authorization": ("Access Control", "Authorisation", "Missing authorisation check", None),
    "access control/incorrect authorization": ("Access Control", "Authorisation", "Incorrect authorisation check", None),
    "access control/arbitrary call": ("Access Control", "Arbitrary Execution", "Unrestricted external call", None),
    "access control/arbitrary recipient": ("Access Control", "Authorisation", "Arbitrary recipient", None),
    "access control/privilege escalation": ("Access Control", "Privilege", "Privilege escalation", None),
    "access control/initializer access": ("Access Control", "Initialisation", "Initializer access", None),
}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").replace("  ", " ")).strip().lower()


def classify(finding: dict) -> dict:
    classes = finding.get("vulnerability_classes") or []
    if not classes:
        return {"category": "Unknown", "family": None, "class": None, "subtype": None,
                "evidence_type": "unknown", "c4_original": [],
                "note": "the record carries no vulnerability class; nothing is inferred"}

    labels = []
    for raw in classes:
        n = _norm(raw)
        hit = KNOWN.get(n)
        if hit is None:
            top = CATEGORY_MAP.get(n.split("/")[0].strip(), None)
            labels.append({"category": top or "Unknown", "family": None,
                           "class": n.split("/")[-1] if "/" in n else n,
                           "subtype": None, "evidence_type": "derived_fact",
                           "rule": "top-level matched, lower levels not attested",
                           "c4_string": raw})
            continue
        cat, fam, cls, sub = hit
        labels.append({"category": cat, "family": fam, "class": cls, "subtype": sub,
                       "evidence_type": "derived_fact",
                       "rule": "exact match against the taxonomy table in scripts/taxonomy.py",
                       "c4_string": raw})

    primary = labels[0]
    return {
        "category": primary["category"],
        "family": primary["family"],
        "class": primary["class"],
        "subtype": primary["subtype"],
        "evidence_type": primary["evidence_type"],
        "labels": labels,
        "multi_label": len(labels) > 1,
        "c4_original": classes,
        "vocabulary": {"top_level": list(TOP_LEVEL)},
        "note": "labels are preserved alongside v1's C4 strings; nothing is overwritten",
    }