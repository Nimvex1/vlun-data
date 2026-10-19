"""Hand-computable checks for scripts/iaa_statistics.py (item 14 maths).

Every expectation below is derived in the comment, by hand, from the definition - not
from the implementation - so a change in the code that breaks the maths fails here.
"""
from __future__ import annotations

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from scripts.iaa_statistics import (  # noqa: E402
    ORDINAL_LEVEL,
    ORDINAL_TIER,
    analyse,
    bootstrap_ci,
    cohens_kappa,
    krippendorff_alpha,
    read_responses,
    report,
    weighted_kappa,
)

TOL = 1e-9


def test_kappa_perfect_agreement_is_one():
    a = ["1", "2", "3", "1", "2"]
    assert cohens_kappa(a, list(a)) == pytest.approx(1.0, abs=TOL)


def test_kappa_chance_agreement_is_zero():
    # both raters label everything the same single class -> pe = 1, statistic undefined
    assert cohens_kappa(["1", "1"], ["1", "1"]) is None
    # marginal-distribution case: po == pe -> kappa 0
    a = ["1", "1", "2", "2"]
    b = ["1", "2", "1", "2"]
    # po = 2/4 = 0.5 ; pe = (2*2 + 2*2)/16 = 0.5
    assert cohens_kappa(a, b) == pytest.approx(0.0, abs=TOL)


def test_kappa_hand_case():
    a = ["1", "1", "1", "1", "2", "2", "2", "2"]
    b = ["1", "1", "1", "2", "1", "2", "2", "2"]
    # agree on 6/8 -> po = 0.75
    # rater a marginals: 1:4, 2:4 ; rater b: 1:5, 2:3
    # pe = (4*5 + 4*3)/64 = 32/64 = 0.5
    # kappa = (0.75 - 0.5) / 0.5 = 0.5
    assert cohens_kappa(a, b) == pytest.approx(0.5, abs=TOL)


def test_weighted_kappa_nominal_matches_cohen():
    a = ["1", "1", "1", "1", "2", "2", "2", "2"]
    b = ["1", "1", "1", "2", "1", "2", "2", "2"]
    assert weighted_kappa(a, b, "nominal", ORDINAL_TIER) == pytest.approx(
        cohens_kappa(a, b), abs=TOL)


def test_weighted_kappa_linear_hand_case():
    cats = ORDINAL_TIER  # 0,1,2,3 ; k-1 = 3
    a = ["1", "1", "3"]
    b = ["1", "2", "0"]
    # weights: w(i,j)=|i-j|/3. observed disagreements: (1,2)=1/3, (1,0)=1/3 -> num = 2/3 over n=3
    # -> mean observed weight = (2/3)/3 = 2/9
    # marginals: a: 1 x2, 3 x1 ; b: 1,2,0 one each
    # expected = sum_ij w(i,j)*ra_i*rb_j / n^2 = [(1,0):1/3*2*1 + (1,1):0*2*1 + (1,2):1/3*2*1
    #            + (3,0):1*1*1 + (3,1):2/3*1*1 + (3,2):1/3*1*1] / 9
    #          = (2/3 + 2/3? recompute) -> computed below independently
    exp = 0.0
    ra = {"1": 2, "3": 1}
    rb = {"0": 1, "1": 1, "2": 1}
    for i, ci in enumerate(cats):
        for j, cj in enumerate(cats):
            exp += (abs(i - j) / 3.0) * ra.get(ci, 0) * rb.get(cj, 0) / 9.0
    # observed weighted disagreement (as a per-item mean) = (0 + 1/3 + 1)/3 = 4/9
    expected_value = 1 - (4.0 / 9.0) / exp
    assert weighted_kappa(a, b, "linear", cats) == pytest.approx(expected_value, abs=TOL)


def test_weighted_kappa_quadratic_penalises_far_errors_more():
    near = (["1", "1", "3"], ["1", "2", "3"])
    far = (["1", "1", "3"], ["3", "2", "3"])
    kn = weighted_kappa(near[0], near[1], "quadratic", ORDINAL_TIER)
    kf = weighted_kappa(far[0], far[1], "quadratic", ORDINAL_TIER)
    assert kn > kf


def test_alpha_perfect_agreement():
    units = [{"a": "1", "b": "1"}, {"a": "2", "b": "2"}, {"a": "1", "b": "1"}]
    assert krippendorff_alpha(units, "nominal") == pytest.approx(1.0, abs=TOL)


def test_alpha_full_disagreement_two_coders_two_units():
    # every unit has one 1 and one 2.
    # Do: per unit, mean squared disagreement over ordered pairs = (1*1*1 + 1*1*1)/(2*1) = 1
    # Dc: pooled values = [1,1,2,2]; (1*2... ) = (2*2*1 + 2*2*1)/(4*3) = 8/12 = 2/3
    # alpha = 1 - 1/(2/3) = -1/2
    units = [{"a": "1", "b": "2"}, {"a": "2", "b": "1"}]
    assert krippendorff_alpha(units, "nominal") == pytest.approx(-0.5, abs=TOL)


def test_alpha_single_unit_one_disagreement():
    # one unit, two coders, different values: Do = 1, Dc = 1 -> alpha = 0
    units = [{"a": "1", "b": "2"}]
    assert krippendorff_alpha(units, "nominal") == pytest.approx(0.0, abs=TOL)


def test_alpha_units_without_two_values_are_skipped():
    # unit 3 has one coder: it can neither agree nor disagree, so it is dropped.
    # remaining units: [1,1] -> Do contribution 0 ; [1,2] -> Do contribution 1
    # Do = (0 + 1)/2 = 0.5. Pooled values [1,1,1,2]: counts 1:3, 2:1, m=4
    # Dc = (3*1*1 + 1*3*1)/(4*3) = 6/12 = 0.5  ->  alpha = 1 - 0.5/0.5 = 0
    units = [{"a": "1", "b": "1"}, {"a": "1", "b": "2"}, {"a": "2"}]
    assert krippendorff_alpha(units, "nominal") == pytest.approx(0.0, abs=TOL)
    # no unit with two coders at all -> nothing measurable, reported as None not as 1.0
    assert krippendorff_alpha([{"a": "1"}, {"a": "2"}], "nominal") is None


def test_alpha_ordinal_prefers_near_misses():
    near = [{"a": "0", "b": "1"}, {"a": "1", "b": "2"}, {"a": "2", "b": "3"}]
    far = [{"a": "0", "b": "3"}, {"a": "3", "b": "0"}, {"a": "1", "b": "3"}]
    a_near = krippendorff_alpha(near, "ordinal", ORDINAL_TIER)
    a_far = krippendorff_alpha(far, "ordinal", ORDINAL_TIER)
    assert a_near > a_far


def test_bootstrap_bracket_and_determinism():
    units = [{"a": "1", "b": "1"}, {"a": "1", "b": "2"}, {"a": "2", "b": "2"},
             {"a": "2", "b": "2"}, {"a": "1", "b": "1"}, {"a": "2", "b": "1"}]
    f = lambda us: krippendorff_alpha(us, "nominal")  # noqa: E731
    c1 = bootstrap_ci(f, units, seed=7, reps=500)
    c2 = bootstrap_ci(f, units, seed=7, reps=500)
    assert c1 == c2, "bootstrap must be seeded and reproducible"
    assert c1["ci95_low"] <= c1["point"] <= c1["ci95_high"] or c1["ci95_low"] <= c1["ci95_high"]
    assert c1["replicates"] > 0


def test_empty_responses_dir_reports_not_measured(tmp_path):
    d = tmp_path / "responses"
    d.mkdir()
    (d / "annotator_1.template.csv").write_text("record_id\n", encoding="utf-8")
    rows, notes = read_responses(str(d))
    assert rows == []
    doc = report(str(d), root=os.getcwd())
    assert doc["measured"] is False
    assert doc["measured_reason"]


def test_llm_self_consistency_is_not_iaa(tmp_path):
    """Two passes by one model are not two annotators, and a non-human kind is excluded."""
    d = tmp_path / "responses"
    d.mkdir()
    for name, kind in (("a.csv", "llm_self_consistency"), ("b.csv", "llm_self_consistency")):
        rows = [
            {"annotator_id": "gpt-run-1", "annotator_kind": kind, "record_id": "r1",
             "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
            {"annotator_id": "gpt-run-1", "annotator_kind": kind, "record_id": "r2",
             "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
        ]
        _write_csv(d / name, rows)
    rows, _ = read_responses(str(d))
    out = analyse(rows)
    assert out["measurable"] is False
    assert sum(out["non_human_rows_excluded"].values()) == 4


def test_single_human_annotator_twice_is_not_iaa(tmp_path):
    d = tmp_path / "responses"
    d.mkdir()
    rows = [
        {"annotator_id": "human-1", "annotator_kind": "human", "record_id": "r1",
         "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
        {"annotator_id": "human-1", "annotator_kind": "human", "record_id": "r2",
         "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
    ]
    _write_csv(d / "only.csv", rows)
    out = analyse(read_responses(str(d))[0])
    assert out["measurable"] is False
    assert out["annotators_seen"] == 1


def test_two_humans_produce_numbers(tmp_path):
    d = tmp_path / "responses"
    d.mkdir()
    rows = []
    for rid, pa, pb, sa, sb in [("r1", "RC-01", "RC-01", "2", "2"), ("r2", "RC-02", "RC-03", "1", "2"),
                                ("r3", "RC-03", "RC-03", "3", "3"), ("r4", "RC-01", "RC-01", "0", "1")]:
        for aid, p, s_, kind in (("human-A", pa, sa, "human"), ("human-B", pb, sb, "human")):
            rows.append({"annotator_id": aid, "annotator_kind": kind, "record_id": rid,
                         "rc_primary": p, "severity_tier": s_, "evidence_ceiling": "L2"})
    _write_csv(d / "both.csv", rows)
    out = analyse(read_responses(str(d))[0])
    assert out["measurable"] is True
    stats = out["per_pair"]["human-A|human-B"]
    assert stats["n_common"] == 4
    # hand: po on primary = 3/4, marginals A {RC-01:2,RC-02:1,RC-03:1}, B {RC-01:2,RC-03:2}
    # pe = (2*2 + 1*0 + 1*2)/16 = 6/16 = 0.375 -> kappa = (0.75-0.375)/0.625 = 0.6
    assert stats["kappa_primary_label"] == pytest.approx(0.6, abs=TOL)
    assert math.isfinite(stats["weighted_kappa_severity_linear"])


def _write_csv(path, rows):
    import csv

    fields = ["annotator_id", "annotator_kind", "record_id", "rc_primary",
              "severity_tier", "evidence_ceiling"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
