#!/usr/bin/env python3
"""Gate tests for item 16 (root-cause taxonomy) and item 14's honesty guards.

Each broken fixture under tests/fixtures/broken/ must make the relevant script fail with
a reason that names the defect. The two IAA fixtures are the ones that matter most: a
report that claims a numeric agreement with no responses present, and a report that would
pass LLM self-consistency off as human inter-annotator agreement.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "broken")
sys.path.insert(0, ROOT)


def run(script, *args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", script), *args],
                          capture_output=True, text=True)


def tax_args(tax, assign):
    return ["--root", ROOT, "--taxonomy", tax, "--assignments", assign,
            "--records", os.path.join(ROOT, "derived", "records.jsonl")]


def test_clean_run_passes():
    r = run("validate_taxonomy.py", "--root", ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


def test_impact_written_as_root_cause_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_impact_as_cause.jsonl"),
                                             os.path.join(FIX, "assignments_ok.jsonl")))
    assert r.returncode == 1
    assert "impact language in root-cause field" in r.stderr, r.stderr
    assert "RC-XX" in r.stderr or "RC-01" in r.stderr


def test_primitive_written_as_root_cause_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_primitive_as_cause.jsonl"),
                                             os.path.join(FIX, "assignments_ok.jsonl")))
    assert r.returncode == 1
    assert "primitive language in root-cause field" in r.stderr, r.stderr


def test_unjustified_swc_map_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_unjustified_swc.jsonl"),
                                             os.path.join(FIX, "assignments_ok.jsonl")))
    assert r.returncode == 1
    assert "has no justification" in r.stderr, r.stderr


def test_invented_swc_identifier_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_invented_swc.jsonl"),
                                             os.path.join(FIX, "assignments_ok.jsonl")))
    assert r.returncode == 1
    assert "has not verified" in r.stderr, r.stderr


def test_map_without_justification_or_no_map_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_no_map_no_reason.jsonl"),
                                              os.path.join(FIX, "assignments_ok.jsonl")))
    assert r.returncode == 1
    assert "no_map without a reason" in r.stderr or "no entries and no explicit no_map" in r.stderr, r.stderr


def test_missing_exclusion_rule_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_no_exclusions.jsonl"),
                                             os.path.join(FIX, "assignments_ok.jsonl")))
    assert r.returncode == 1
    assert "at least two exclusion rules" in r.stderr, r.stderr


def test_assignment_to_unknown_category_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_valid.jsonl"),
                                             os.path.join(FIX, "assignments_unknown_category.jsonl")))
    assert r.returncode == 1
    assert "outside the closed vocabulary" in r.stderr, r.stderr


def test_assignment_for_unknown_record_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_valid.jsonl"),
                                             os.path.join(FIX, "assignments_unknown_record.jsonl")))
    assert r.returncode == 1
    assert "unknown record id" in r.stderr, r.stderr


def test_unlabelled_without_reason_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_valid.jsonl"),
                                             os.path.join(FIX, "assignments_unlabelled_no_reason.jsonl")))
    assert r.returncode == 1
    assert "unlabelled without a reason" in r.stderr, r.stderr


def test_exclusive_labels_together_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_valid.jsonl"),
                                             os.path.join(FIX, "assignments_exclusive_pair.jsonl")))
    assert r.returncode == 1
    assert "mutually exclusive" in r.stderr, r.stderr


def test_evidence_claim_contradicting_the_floor_fails():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_valid.jsonl"),
                                             os.path.join(FIX, "assignments_evidence_mismatch.jsonl")))
    assert r.returncode == 1
    assert "contradicts" in r.stderr, r.stderr


def test_facet_must_not_be_assignable():
    r = run("validate_taxonomy.py", *tax_args(os.path.join(FIX, "taxonomy_facet_assignable.jsonl"),
                                             os.path.join(FIX, "assignments_ok.jsonl")))
    assert r.returncode == 1
    assert "facets are not assignable" in r.stderr, r.stderr


def test_check_regenerates_byte_identical_outputs():
    r = run("validate_taxonomy.py", "--root", ROOT, "--check")
    assert r.returncode == 0, r.stdout + r.stderr


def test_iaa_report_claiming_numbers_without_responses_is_rejected(tmp_path):
    empty = tmp_path / "responses"
    empty.mkdir()
    bad = json.load(open(os.path.join(FIX, "iaa_report_measured_without_responses.json"), encoding="utf-8"))
    p = tmp_path / "report.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    r = run("iaa_statistics.py", "--audit-report", str(p), "--responses", str(empty))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "no completed rows" in r.stderr, r.stderr


def test_iaa_report_passing_llm_self_consistency_off_as_human_is_rejected(tmp_path):
    resp = tmp_path / "responses"
    resp.mkdir()
    rows = [
        {"annotator_id": "model-run-a", "annotator_kind": "llm_self_consistency",
         "record_id": "r1", "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
        {"annotator_id": "model-run-b", "annotator_kind": "llm_self_consistency",
         "record_id": "r1", "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
        {"annotator_id": "model-run-a", "annotator_kind": "llm_self_consistency",
         "record_id": "r2", "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
        {"annotator_id": "model-run-b", "annotator_kind": "llm_self_consistency",
         "record_id": "r2", "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
    ]
    import csv

    fields = list(rows[0])
    with open(resp / "runs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    bad = json.load(open(os.path.join(FIX, "iaa_report_llm_as_iaa.json"), encoding="utf-8"))
    p = tmp_path / "report.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    r = run("iaa_statistics.py", "--audit-report", str(p), "--responses", str(resp))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "self-consistency" in r.stderr, r.stderr


def test_shipped_iaa_status_says_not_measured():
    doc = json.load(open(os.path.join(ROOT, "reports", "iaa_status.json"), encoding="utf-8"))
    assert doc["measured"] is False
    assert doc["measured_reason"]
    assert "measured" not in ("true", True)


def test_taxonomy_is_not_claimed_as_a_community_standard():
    for name in ("root_cause_v1.md", "derivation_log.md"):
        text = open(os.path.join(ROOT, "taxonomy", name), encoding="utf-8").read()
        low = text.lower()
        assert "community standard" in low, "%s must state the standard caveat" % name
        assert "project-local" in low or "not a community standard" in low
        # the file must not assert adoption
        for phrase in ("is a community standard", "the community standard", "adopted as a standard"):
            assert phrase not in low.replace("not a community standard", ""), (name, phrase)
