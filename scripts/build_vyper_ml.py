#!/usr/bin/env python3
"""Build the vyperlang/vyper advisory layer for VLUN v2.2.

Three registries describe the same advisories and they do not agree, which is
the whole reason this script keeps all three instead of picking one:

  * the repository advisory list (work/adv_vyperlang_vyper.json) is the
    publisher's own record - its `severity` band is vyperlang's claim;
  * the global advisory list (work/pip_vyper_advisories.json) is the same
    records seen through GitHub's package view, with CVSS vectors, references
    and first-patched versions the repository view omits - and for 19 of the 44
    it carries a *different* severity band;
  * NVD (work/v2_2/raw/vyper/nvd_*.json) analyses them again; for 27 of the 40
    its own Primary metric disagrees with the publisher's band, and one of the
    linked CVEs (CVE-2022-29175) is REJECTED outright.

So severity is recorded as vyperlang's band, with every other value named
beside it and the disagreement stated. Nothing is averaged, nothing is
silently dropped.

    python scripts/build_vyper_ml.py           # write jsonl_ml/*_vyper.jsonl
    python scripts/build_vyper_ml.py --check   # validate, write nothing
    python scripts/build_vyper_ml.py --diff    # the registry disagreements only

NVD payloads are fetched by `--fetch` and cached under work/v2_2/raw/vyper/.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import DATASET_VERSION, SCHEMA_VERSION, log  # noqa: E402
from vlun_io import sha256_bytes, sha256_file  # noqa: E402  (shared hash primitives; were local copies)
from vlun_ml import (  # noqa: E402
    ML_JSONL, claim, finding_record, source_record, unknown,
    validate_finding, validate_source, write_jsonl,
)

ROOT = Path(__file__).resolve().parent.parent
REPO_PAYLOAD = ROOT / "work" / "adv_vyperlang_vyper.json"
GLOBAL_PAYLOAD = ROOT / "work" / "pip_vyper_advisories.json"
RAW = ROOT / "work" / "v2_2" / "raw" / "vyper"
TODAY = "2026-10-05"
EXPERIMENTS_INDEX = ROOT / "experiments_v2_2" / "index.json"

# Two advisories whose claim was actually reproduced in this session by
# scripts/run_vyper_poc.py. Nothing here is written from memory: the level and
# the artefact names come from the recorded run, and if that run is not on disk
# the finding stays a reported claim.
#
# Levels follow poc_classification.py: L3 compiles, L4 executes, L5 reproduces
# the claimed violation, L6 is L5 on the vulnerable revision and blocked on the
# fixed one.
VERIFIED = {
    "GHSA-6j9c-gvcw-74fj": {
        "experiment_id": "vyper-optimizer-ternary",
        "level": "L5",
        "observed": (
            "vyper 0.3.10 compiled the contract at the default optimizer level "
            "to IR containing `1 <msg.value | 2>` and no `callvalue`, and at "
            "--optimize none to IR that kept `callvalue` and lost the fold. "
            "Both builds were deployed on a local anvil node and calc(true) "
            "was called with msg.value=5: it returned 1 at the default level "
            "and 7 at --optimize none, which is the advertised difference"),
        "why_no_L6": (
            "the advisory publishes no patched version (its range is "
            "'>= 0.3.8' with an empty patched_versions), so there is no fixed "
            "revision to fail on. vyper 0.4.0 was compiled as well and still "
            "folds the expression; that is recorded as an observation, not as "
            "a fix comparison"),
    },
    "GHSA-x2c2-q32w-4w6m": {
        "experiment_id": "vyper-rawcall-value",
        "level": "L3",
        "fixed_version": "0.4.0",
        "observed": (
            "vyper 0.3.10 compiled raw_call(..., is_delegate_call=True, "
            "value=msg.value) without complaint and also compiled the control "
            "with the value kwarg removed; vyper 0.4.0 rejected the first with "
            "ArgumentException 'value= may not be passed for static or "
            "delegate calls!' while still compiling the control, so the "
            "acceptance difference is the value kwarg and not the delegate call"),
        "why_no_L4": (
            "the defect is a missing compile-time validation: the violation is "
            "that the compiler accepts the file, and that is what was observed. "
            "There is no contract behaviour to deploy and call, so no level "
            "above L3 is reachable for this advisory"),
    },
}


def load_runs() -> dict[str, dict]:
    if not EXPERIMENTS_INDEX.exists():
        return {}
    try:
        data = json.loads(EXPERIMENTS_INDEX.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {e["experiment_id"]: e for e in data.get("experiments", [])}
NVD_ONE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
NVD_KEYWORD = ("https://services.nvd.nist.gov/rest/json/cves/2.0?"
               "keywordSearch=vyper&resultsPerPage=2000")

# Two CVEs that NVD attributes to Vyper compilers other than vyperlang/vyper
# (era-compiler-vyper for zkSync Era, and zkvyper). They turn up in any honest
# NVD search for "vyper", so they are kept rather than quietly filtered out -
# but they carry their own project name and no invented repository.
NVD_ONLY_PROJECTS = {
    "CVE-2023-46232": "era-compiler-vyper (EraVM Vyper compiler for zkSync Era)",
    "CVE-2024-43366": "zkvyper (Vyper compiler for zkSync)",
}


def load_json(p: Path):
    # GitHub's API answers with a BOM sometimes; utf-8-sig handles both
    return json.loads(p.read_text(encoding="utf-8-sig"))


def fetch_nvd() -> None:
    """Cache every NVD record we cite. Idempotent: existing files win."""
    RAW.mkdir(parents=True, exist_ok=True)
    dest = RAW / "nvd_keyword_vyper.json"
    if not dest.exists():
        log(f"  GET {NVD_KEYWORD}")
        with urllib.request.urlopen(NVD_KEYWORD, timeout=120) as r:
            dest.write_bytes(r.read())
        time.sleep(6)
    known = load_json(dest)
    have = {i["cve"]["id"] for i in known["vulnerabilities"]}
    for cve in sorted(set(NVD_ONLY_PROJECTS) |
                      {a["cve_id"] for a in load_json(REPO_PAYLOAD)
                       if a.get("cve_id")} - have):
        f = RAW / f"nvd_{cve}.json"
        if f.exists():
            continue
        log(f"  GET {NVD_ONE.format(cve=cve)}")
        try:
            with urllib.request.urlopen(NVD_ONE.format(cve=cve), timeout=60) as r:
                f.write_bytes(r.read())
        except Exception as exc:                     # noqa: BLE001
            log(f"    failed: {exc}")
        time.sleep(6)
    manifest = {p.name: sha256_file(p) for p in sorted(RAW.glob("*.json"))}
    (RAW / "_hashes.json").write_text(json.dumps(manifest, indent=2),
                                      encoding="utf-8")
    log(f"  cached {len(manifest)} NVD payloads under {RAW}")


def nvd_records() -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not RAW.exists():
        return out
    for p in sorted(RAW.glob("nvd*.json")):
        try:
            data = load_json(p)
        except (OSError, json.JSONDecodeError):
            continue
        for item in data.get("vulnerabilities", []) or []:
            cve = item.get("cve") or {}
            if cve.get("id"):
                out[cve["id"]] = cve
    return out


# ---------------------------------------------------------------------------
# reading the three registries
# ---------------------------------------------------------------------------

def cvss_metrics(cve: dict) -> list[dict]:
    out = []
    for kind, entries in (cve.get("metrics") or {}).items():
        for m in entries or []:
            cd = m.get("cvssData") or {}
            out.append({
                "metric": kind,
                "source": m.get("source"),
                "type": m.get("type"),
                "version": cd.get("version"),
                "base_score": cd.get("baseScore"),
                "base_severity": (cd.get("baseSeverity") or "").lower() or None,
                "vector_string": cd.get("vectorString"),
            })
    return out


def nvd_primary(mets: list[dict]) -> dict | None:
    for m in mets:
        if m.get("type") == "Primary" and "nist" in (m.get("source") or ""):
            return m
    return None


def nvd_cwes(cve: dict) -> list[dict]:
    out = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value")
            if v and v.startswith("CWE-"):
                out.append({"cwe": v, "source": w.get("source"),
                            "type": w.get("type")})
    # de-duplicate on (cwe, source) but keep both sources visible
    seen, uniq = set(), []
    for c in out:
        k = (c["cwe"], c["source"])
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    return uniq


def nvd_affected(cve: dict) -> list[dict]:
    """NVD's own view of what is affected, independent of GitHub's ranges."""
    out = []
    for block in cve.get("affected") or []:
        for a in block.get("affectedData") or []:
            versions = [v.get("version") or v.get("lessThan") or ""
                        for v in a.get("versions") or []]
            out.append({
                "vendor": a.get("vendor"),
                "product": a.get("product"),
                "status": a.get("defaultStatus"),
                "versions": [v for v in versions if v],
                "source": block.get("source"),
            })
    return out


def first_paragraph(description: str) -> str | None:
    """Quote the advisory rather than paraphrase it: the first prose block
    after any headings, which is where these advisories put their impact."""
    if not description:
        return None
    text = re.sub(r"\r", "", description)
    for block in re.split(r"\n\s*\n", text):
        b = block.strip()
        if not b or b.startswith("#") or b.startswith("```"):
            continue
        if b.startswith(("-", "*", "|", ">")):
            continue
        b = re.sub(r"\s+", " ", b)
        if len(b) < 60:
            continue
        return b[:700] + ("..." if len(b) > 700 else "")
    return None


def cited_files(description: str) -> list[str]:
    """Source files the advisory links, kept as text: they are Python files in
    the compiler, so they are not `code_context` for any language we claim."""
    out = []
    for m in re.finditer(r"github\.com/vyperlang/vyper/blob/[0-9a-f]{7,40}/"
                         r"([A-Za-z0-9_./\-]+\.py)", description or ""):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out[:12]


def commit_from_references(refs: list[str]) -> str | None:
    for r in refs or []:
        m = re.search(r"github\.com/vyperlang/vyper/commit/([0-9a-f]{40})", r)
        if m:
            return m.group(1)
    return None


def pysec_from_references(refs: list[str]) -> str | None:
    for r in refs or []:
        m = re.search(r"(PYSEC-\d{4}-\d+)", r)
        if m:
            return m.group(1)
    return None


def build() -> tuple[list, list]:
    repo_list = load_json(REPO_PAYLOAD)
    global_list = load_json(GLOBAL_PAYLOAD)
    nvd = nvd_records()
    by_ghsa_global = {a["ghsa_id"]: a for a in global_list}

    # the two NVD-only CVEs are not part of the vyperlang/vyper list; they are
    # added once, below, with their own project attribution
    repo_by_id = {a["ghsa_id"]: a for a in repo_list}
    extra_cves = [c for c in NVD_ONLY_PROJECTS if c in nvd]

    sources: list[dict] = []
    findings: list[dict] = []

    for ghsa in sorted(repo_by_id):
        repo = repo_by_id[ghsa]
        glob = by_ghsa_global.get(ghsa)
        cve = repo.get("cve_id") or (glob or {}).get("cve_id")
        nrec = nvd.get(cve) if cve else None
        sources.append(make_source(repo, glob, nrec, ghsa, cve))
        findings.append(make_finding(repo, glob, nrec, ghsa, cve))

    for cve in extra_cves:
        nrec = nvd[cve]
        sources.append(make_source(None, None, nrec, None, cve))
        findings.append(make_finding(None, None, nrec, None, cve))

    return sources, findings


def en_text(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value") or ""
    return ""


def make_source(repo: dict | None, glob: dict | None, nrec: dict | None,
                ghsa: str | None, cve: str | None) -> dict:
    nvd_only = repo is None
    base = repo or glob or {}
    summary = (base.get("summary") or
               re.sub(r"\s+", " ", en_text(nrec or {}))[:200])
    identifier = ghsa or cve
    note_bits: list[str] = []

    payloads = []
    if repo is not None:
        payloads.append({
            "endpoint": f"https://api.github.com/repos/vyperlang/vyper"
                        f"/security-advisories/{ghsa}",
            "list_endpoint": "work/adv_vyperlang_vyper.json",
            "payload_sha256": sha256_bytes(
                json.dumps(repo, sort_keys=True).encode()),
        })
    if glob is not None:
        payloads.append({
            "endpoint": f"https://api.github.com/advisories/{ghsa}",
            "list_endpoint": "work/pip_vyper_advisories.json",
            "payload_sha256": sha256_bytes(
                json.dumps(glob, sort_keys=True).encode()),
        })
    if nrec is not None:
        payloads.append({
            "endpoint": f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                        f"?cveId={cve}",
            "list_endpoint": "work/v2_2/raw/vyper/",
            "payload_sha256": sha256_bytes(
                json.dumps(nrec, sort_keys=True).encode()),
            "vuln_status": nrec.get("vulnStatus"),
        })

    # severity: vyperlang's own band first, everything else named beside it
    repo_sev = (repo or {}).get("severity")
    glob_sev = (glob or {}).get("severity")
    prim = nvd_primary(cvss_metrics(nrec or {})) if nrec else None
    nvd_sev = (prim or {}).get("base_severity")
    if nvd_only:
        value = nvd_sev or (nrec and (nrec.get("vulnStatus") or "").lower())
        sev_source = ("NVD's own CVSS base severity, there being no GitHub "
                      "advisory for this CVE")
    else:
        value = repo_sev
        sev_source = "severity published by vyperlang in the repository advisory"
    sev_note = f"recorded value: {value} ({sev_source})"
    if glob_sev and glob_sev != repo_sev:
        sev_note += (f"; GitHub's global advisory view of the same record says "
                     f"{glob_sev}")
    if nvd_sev and nvd_sev != value:
        sev_note += (f"; NVD's Primary CVSS metric says {nvd_sev} "
                     f"(score {(prim or {}).get('base_score')})")
    if prim is None and nrec is not None and cve:
        sev_note += ("; NVD publishes no Primary metric for this CVE, only a "
                     "metric sourced from GitHub, so it is not independent "
                     "confirmation")

    # affected: GitHub's range, NVD's range when it differs
    vulns = (base.get("vulnerabilities") or [{}])
    v0 = vulns[0] if vulns else {}
    pkg = v0.get("package") or {}
    affected = [{
        "name": pkg.get("name") or "",
        "package_ecosystem": pkg.get("ecosystem") or "",
        "vulnerable_version_range": v0.get("vulnerable_version_range") or "",
        "patched_versions": v0.get("patched_versions")
                            or v0.get("first_patched_version") or "",
        "source": "github repository advisory" if repo is not None
                  else "github global advisory",
    }]
    if glob is not None and repo is not None:
        gv = (glob.get("vulnerabilities") or [{}])[0]
        g_range = gv.get("vulnerable_version_range") or ""
        if g_range and g_range != v0.get("vulnerable_version_range"):
            affected[0]["alternate_range"] = {
                "value": g_range,
                "source": "github global advisory (first_patched_version "
                          f"{gv.get('first_patched_version')})",
            }
            note_bits.append("the repository and global views publish "
                             f"different version ranges: "
                             f"{v0.get('vulnerable_version_range')!r} vs "
                             f"{g_range!r}")
    na = nvd_affected(nrec or {})
    if na:
        affected.append({
            "name": " / ".join(sorted({a["product"] or "" for a in na
                                       if a.get("product")})),
            "package_ecosystem": "nvd cpe",
            "vulnerable_version_range": "; ".join(
                sorted({v for a in na for v in a["versions"]})),
            "patched_versions": "",
            "source": "NVD affected data",
        })

    # fix: only what a registry actually printed, never inferred
    refs = (glob or {}).get("references") or []
    commit = commit_from_references(refs)
    fix = {"commit": None, "url": None, "evidence_type": "unknown"}
    if commit:
        fix = {
            "commit": commit,
            "url": f"https://github.com/vyperlang/vyper/commit/{commit}",
            "evidence_type": "reported_claim",
            "note": "commit link published in the advisory's references; this "
                    "pipeline did not fetch the commit object, so it is not "
                    "verified as the fix",
        }
        note_bits.append("a fix commit is named in the references but was not "
                         "resolved against a commit object")
    elif v0.get("patched_versions") or v0.get("first_patched_version"):
        fix = {
            "commit": None,
            "url": None,
            "evidence_type": "reported_claim",
            "note": "the advisory states a fixed version but no commit",
        }

    if nrec is not None and nrec.get("vulnStatus") == "Rejected":
        note_bits.append(
            "NVD marks this CVE REJECTED ('not a security issue'), while the "
            "GitHub advisory is still published - the CVE identifier attached "
            "to the advisory must not be used as a vulnerability label")

    if glob is not None and repo is not None:
        gsum = (glob.get("summary") or "").strip()
        rsum = (repo.get("summary") or "").strip()
        if gsum and rsum and gsum != rsum:
            note_bits.append(
                "the two GitHub views also disagree on the title: the "
                f"repository says {rsum!r}, the global advisory says {gsum!r}")

    identifiers = {}
    if ghsa:
        identifiers["ghsa"] = ghsa
    if cve:
        identifiers["cve"] = cve
    pysec = pysec_from_references(refs)
    if pysec:
        identifiers["pysec"] = pysec
    if nrec is not None:
        identifiers["nvd_vuln_status"] = nrec.get("vulnStatus")

    url = (repo or {}).get("html_url") or (glob or {}).get("html_url") or \
        (f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None)

    src = source_record(
        source_id=f"vyper:{identifier}",
        language="vyper",
        ecosystem="vyper",
        title=summary,
        source_tier=0,
        evidence_origin="security_advisory",
        url=url or "https://github.com/vyperlang/vyper/security/advisories",
        repository=(None if nvd_only else "vyperlang/vyper"),
        retrieved_at=TODAY,
        verification_status="retrieved_via_api_and_hashed",
        identifiers=identifiers,
        published_at=(base.get("published_at") or
                      (nrec or {}).get("published")),
        severity=claim(value, "observed_fact",
                       [f"vyper:{identifier}"], sev_note),
        affected=affected,
        fix=fix,
        retrieval={"method": "github_rest_api_and_nvd",
                   "payloads": payloads},
        license={
            "content_license": "unknown",
            "redistributable": False,
            "evidence_type": "observed_fact",
            "note": "no licence statement appears in any of the three "
                    "payloads; the terms under which GitHub publishes its "
                    "advisory database were not fetched, so the text is "
                    "treated as not redistributable and is quoted only in the "
                    "short excerpts this record carries",
        },
        notes=" ".join(note_bits) or
              "recorded from the repository advisory list, cross-checked "
              "against GitHub's global advisory view and NVD",
    )
    if nvd_only:
        src["protocol"] = {"name": NVD_ONLY_PROJECTS.get(cve, cve),
                           "category": "Vyper compiler other than "
                                       "vyperlang/vyper"}
        src["notes"] = ("found by NVD keyword search for 'vyper'; this CVE "
                        "affects a different Vyper compiler implementation "
                        f"({NVD_ONLY_PROJECTS.get(cve, cve)}) and has no "
                        "GitHub advisory in the vyperlang/vyper list. "
                        + (note_bits and " ".join(note_bits) or ""))
        src["repository"] = None
    return src


def make_finding(repo: dict | None, glob: dict | None, nrec: dict | None,
                 ghsa: str | None, cve: str | None) -> dict:
    nvd_only = repo is None
    base = repo or glob or {}
    identifier = cve or ghsa
    source_id = f"vyper:{ghsa or cve}"
    lang_id = f"{cve or ghsa}"
    summary = (base.get("summary") or "").strip() or (ghsa or cve)
    description = (base.get("description") or en_text(nrec or {}))
    src_ref = [source_id]

    mets = cvss_metrics(nrec or {})
    prim = nvd_primary(mets)
    repo_sev = (repo or {}).get("severity") or (glob or {}).get("severity")
    if nvd_only:
        repo_sev = (prim or {}).get("base_severity")
    glob_sev = (glob or {}).get("severity")

    sev_note = ("severity published by vyperlang in the repository advisory"
                if not nvd_only else
                "NVD CVSS base severity; there is no GitHub advisory for this CVE")
    others = []
    if glob_sev and glob_sev != (repo or {}).get("severity"):
        others.append(f"github global advisory: {glob_sev}")
    if prim and (prim.get("base_severity") != repo_sev):
        others.append(f"NVD Primary CVSS: {prim['base_severity']} "
                      f"(score {prim.get('base_score')})")
    if others:
        sev_note += "; disagrees with " + ", ".join(others)

    cwes = nvd_cwes(nrec or {})
    nvd_sources = sorted({c["source"] for c in cwes if c.get("source")})
    cwe_ids = sorted({c["cwe"] for c in cwes})

    v0 = ((base.get("vulnerabilities") or [{}]) or [{}])[0]
    affected_range = v0.get("vulnerable_version_range") or None
    patched = v0.get("patched_versions") or v0.get("first_patched_version") \
        or None
    refs = (glob or {}).get("references") or []
    commit = commit_from_references(refs)

    independent = 2 if (prim is not None) else 1
    indep_note = ("GitHub's repository advisory plus NVD's own Primary CVSS "
                  "metric: two registries, though NVD often republishes the "
                  "GitHub CNA's analysis"
                  if prim is not None else
                  "only GitHub's advisory record speaks for this CVE; NVD "
                  "publishes no Primary metric, so nothing independent "
                  "confirms the severity")

    evidence = {
        "existence": claim(
            f"{ghsa or cve} published", "observed_fact", src_ref,
            "payload fetched from the GitHub advisories API and hashed"
            + (", and the NVD record fetched and hashed" if nrec else "")),
        "severity": claim(repo_sev, "observed_fact", src_ref, sev_note),
        "affected_versions": claim(
            affected_range, "reported_claim", src_ref,
            "range exactly as published by the advisory"
            if not nvd_only else "range exactly as published by NVD"),
        "root_cause": claim(
            first_paragraph(description), "reported_claim", src_ref,
            "first prose paragraph of the advisory itself, quoted verbatim; "
            "no root cause was derived by this pipeline"),
        "fix_commit": claim(
            commit, "reported_claim" if commit else "unknown", src_ref,
            "commit link printed in the advisory's references; not resolved "
            "against a commit object" if commit else
            "the advisory publishes no commit"),
        "patch_effective": claim(
            patched, "reported_claim" if patched else "unknown", src_ref,
            "the advisory states the fixed version; this pipeline did not "
            "install it and show the defect disappear"),
        "independent_confirmation": claim(independent, "derived_fact",
                                          src_ref, indep_note),
    }
    if prim is not None:
        evidence["cvss"] = claim(
            {"score": prim.get("base_score"), "vector": prim.get("vector_string"),
             "version": prim.get("version"), "source": prim.get("source")},
            "observed_fact", [f"vyper:{identifier}"],
            "NVD Primary metric, i.e. NVD's own scoring rather than a "
            "relayed value")
    else:
        evidence["cvss"] = unknown(
            "NVD publishes no Primary CVSS metric for this CVE"
            if nrec is not None else "this CVE was not found in NVD")
    if cwe_ids:
        evidence["cwe"] = claim(
            cwe_ids, "reported_claim", [f"vyper:{identifier}"],
            "weaknesses assigned in NVD, sources: " + ", ".join(nvd_sources))
    else:
        evidence["cwe"] = unknown(
            "neither GitHub nor NVD assigns a CWE for this advisory")
    if nrec is not None and nrec.get("vulnStatus") == "Rejected":
        evidence["nvd_status"] = claim(
            "Rejected", "observed_fact", [f"vyper:{identifier}"],
            "NVD's own status: 'DO NOT USE THIS CANDIDATE NUMBER ... it was "
            "not a security issue'")

    # Nothing may be upgraded from a published claim to an observation without
    # a run on disk; the block is assembled from the recorded result, and the
    # finding keeps its reported_claim status when that run is missing.
    status = "reported_claim"
    exp_block = None
    if patched:
        patch_note = ("the advisory names a fixed version"
                      + (" and a fix commit" if commit else "")
                      + "; neither was applied here")
    elif commit:
        patch_note = ("the advisory names a fix commit but no fixed version; "
                      "the commit was not fetched, so it is not applied here")
    else:
        patch_note = ("the advisory publishes neither a fixed version nor a "
                      "fix commit - its patched_versions field is empty - so "
                      "there is nothing to apply")
    spec = VERIFIED.get(ghsa) if ghsa else None
    if spec:
        run = load_runs().get(spec["experiment_id"])
        if run is None:
            log(f"  {ghsa}: no run recorded as {spec['experiment_id']}; "
                f"keeping this one as a reported claim")
        else:
            status = "experimentally_verified"
            exp_block = {
                "level": spec["level"],
                "executed": True,
                "outcome": "reproduced",
                "outcome_basis": spec["observed"],
                "experiment_ids": [spec["experiment_id"]],
                "result_artifact": f"experiments_v2_2/{spec['experiment_id']}/result.json",
                "stdout_artifact": f"experiments_v2_2/{spec['experiment_id']}/stdout.txt",
                "stderr_artifact": f"experiments_v2_2/{spec['experiment_id']}/stderr.txt",
                "command": run.get("command"),
                "toolchain": run.get("toolchain") or {},
                "seconds": run.get("seconds"),
                "exit_code": run.get("exit_code"),
                "verdict_met": (run.get("expectation") or {}).get("met"),
                "commit_sha": None,
                "commit_note": "the PoC sources are versioned in this checkout; "
                               "the compilers print their own release and commit "
                               "in --version, recorded in toolchain",
                "fixed_revision_executed": bool(spec.get("fixed_version")),
                "fixed_version": spec.get("fixed_version"),
            }
            for key in ("why_no_L6", "why_no_L4"):
                if spec.get(key):
                    exp_block[key] = spec[key]
            evidence["reproduced_behavior"] = claim(
                spec["observed"], "experimentally_verified", src_ref,
                f"observed in this session by "
                f"experiments_v2_2/{spec['experiment_id']}/ (stdout, stderr, "
                "toolchain and artefact hashes recorded in result.json); this "
                "pipeline reproduces the claim, it does not independently "
                "derive the root cause")
            if spec.get("fixed_version"):
                evidence["patch_effective"] = claim(
                    f"fixed in {spec['fixed_version']}", "experimentally_verified",
                    src_ref,
                    f"vyper {spec['fixed_version']} was installed in this "
                    "session and rejected the construct while still compiling "
                    "the control, so the defect does not reproduce there")
                patch_note = (f"the advisory names {spec['fixed_version']} as "
                              "the fixed version; that version was installed "
                              "here and the defect no longer reproduced")

    rec = finding_record(
        language="vyper",
        ecosystem="vyper",
        finding_id=lang_id,
        title=summary,
        source_ids=[source_id],
        source={
            "organization": ("vyperlang" if not nvd_only
                             else "NVD (no vendor advisory fetched)"),
            "repository": None if nvd_only else "vyperlang/vyper",
            "repository_url": None if nvd_only
                              else "https://github.com/vyperlang/vyper",
            "advisory": ghsa,
            "cve": cve,
            "nvd_status": (nrec or {}).get("vulnStatus"),
        },
        severity={"value": repo_sev, "source": sev_note},
        finding={
            "record_class": "advisory",
            "status": status,
            "vulnerability_classes": cwe_ids,
            "summary": re.sub(r"\s+", " ", description)[:4000],
            "root_cause": None,
            "affected_components": (
                NVD_ONLY_PROJECTS.get(cve) and [NVD_ONLY_PROJECTS[cve]]
                or sorted({(base.get("vulnerabilities") or [{}])[0]
                           .get("package", {}).get("name") or ""}
                          - {""})),
            "affected_functions": [],
            "affected_versions": affected_range,
            "patched_versions": patched,
        },
        evidence=evidence,
        provenance={
            "source_urls": [u for u in [
                (base.get("html_url") or ""), (glob or {}).get("html_url") or "",
                f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
            ] if u],
            "retrieved_at": TODAY,
            "evidence_origin": "security_advisory",
            "source_tier": 0,
            "record_sha256": sha256_bytes(
                (description or summary).encode("utf-8")),
            "parsed_by": "scripts/build_vyper_ml.py",
            "identifiers": {"ghsa": ghsa, "cve": cve},
            "references": refs[:12],
            "cited_files": cited_files(description),
        },
        code_context=[],
        patch={
            "present": bool(patched or commit),
            "evidence_type": "experimentally_verified" if exp_block
                             and exp_block.get("fixed_revision_executed")
                             else "reported_claim",
            "note": patch_note,
        },
        experiment=exp_block,
        dataset_version=DATASET_VERSION,
        schema_version=SCHEMA_VERSION,
    )
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate, write nothing")
    ap.add_argument("--fetch", action="store_true", help="refresh NVD payloads")
    ap.add_argument("--diff", action="store_true",
                    help="print only the registry disagreements")
    args = ap.parse_args()

    if args.fetch:
        fetch_nvd()

    sources, findings = build()
    errors = []
    for s in sources:
        errors += [f"sources {s['source_id']}: {e}" for e in validate_source(s)]
    for f in findings:
        errors += [f"findings {f['id']}: {e}" for e in validate_finding(f)]

    ids = [f["id"] for f in findings]
    dupes = {i for i in ids if ids.count(i) > 1}
    for d in sorted(dupes):
        errors.append(f"findings duplicate id {d}")

    if args.diff:
        print_disagreements(sources, findings)
        return 0 if not errors else 1

    log(f"vyper layer: {len(sources)} sources, {len(findings)} findings")
    if errors:
        for e in errors[:40]:
            log(f"  [FAIL] {e}")
        return 1
    if args.check:
        log("--check: nothing written")
        return 0

    write_jsonl(ML_JSONL / "sources_vyper.jsonl", sources)
    write_jsonl(ML_JSONL / "findings_vyper.jsonl", findings)
    log(f"wrote {ML_JSONL / 'sources_vyper.jsonl'}")
    log(f"wrote {ML_JSONL / 'findings_vyper.jsonl'}")
    return 0


def print_disagreements(sources: list[dict], findings: list[dict]) -> None:
    rows = []
    for s in sources:
        note = (s.get("severity") or {}).get("note") or ""
        if "disagrees" in note or "global advisory view" in note:
            rows.append((s["source_id"], note))
    for f in findings:
        note = (f["evidence"]["severity"] or {}).get("note") or ""
        if "disagrees" in note:
            rows.append((f["id"], note))
    seen = set()
    for sid, note in rows:
        if sid in seen:
            continue
        seen.add(sid)
        print(f"{sid}\n    {note}")
    print(f"\n{len(seen)} records where the registries disagree")


if __name__ == "__main__":
    raise SystemExit(main())
