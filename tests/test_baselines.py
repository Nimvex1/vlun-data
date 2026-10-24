"""Guard: published baseline reports must match the shipped benchmark files.

The committed baselines were computed against a stale Vbeta population
(624/719 scorable rows) while the shipped Vbeta benchmark files carry
6,219 scorable U rows and 6,935 V rows (13,154 scorable tasks). A stale floor is worse than no floor: a model result read
against it is meaningless. This recomputes the cheap deterministic
summaries from the committed reports and fails when they disagree with
reports/baselines/*.json.

Not a scorer re-run (too slow for every gate); a cross-file consistency
check. `python scripts/score_benchmark.py --baseline ...` regenerates.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

BASE = ROOT / "reports" / "baselines"
BENCH = ROOT / "benchmark"
VBENCH = ROOT / "Vbeta" / "benchmark_vbeta"


def _rows(path: Path) -> int:
    with path.open(encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def _labeled(path: Path) -> int:
    n = 0
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            if json.loads(line).get("answer_key_status") == "labeled":
                n += 1
    return n


class TestBaselinesMatchShippedBenchmarks(unittest.TestCase):
    def test_every_family_scorable_count_matches(self):
        rep = json.loads((BASE / "baseline_majority.json")
                         .read_text(encoding="utf-8"))
        families = rep["families"]
        mismatches = []
        for fam, stats in families.items():
            for base in (BENCH, VBENCH):
                p = base / fam
                if p.is_file():
                    want = _labeled(p)
                    got = stats["scorable"]
                    if want != got:
                        mismatches.append(
                            f"{fam}: baseline={got} file={want}")
                    break
            else:
                mismatches.append(f"{fam}: no benchmark file found")
        self.assertEqual(mismatches, [],
                         "regenerate: python scripts/score_benchmark.py "
                         "--baseline majority --out reports/baselines/"
                         "baseline_majority.json")

    def test_micro_total_equals_sum_of_families(self):
        rep = json.loads((BASE / "baseline_majority.json")
                         .read_text(encoding="utf-8"))
        total = sum(s["scorable"] for s in rep["families"].values())
        self.assertEqual(rep["micro"]["scorable"], total)

    def test_all_six_baselines_agree_on_scorable_set(self):
        want = want_all = want_expl = None
        for n in ("majority", "random_seed7", "frequency_seed7",
                  "first_published", "majority_published", "retrieval"):
            p = BASE / f"baseline_{n}.json"
            rep = json.loads(p.read_text(encoding="utf-8"))
            s = rep["micro"]["scorable"]
            if want is None:
                want = s
            self.assertEqual(s, want, f"baseline_{n}.json disagrees on "
                                      f"the scorable task set")
            a = rep["micro_all_families"]["scorable"]
            if want_all is None:
                want_all = a
            self.assertEqual(a, want_all, f"baseline_{n}.json disagrees on "
                                          f"the all-families scorable set")
            e = rep["micro_exploratory"]["scorable"]
            if want_expl is None:
                want_expl = e
            self.assertEqual(e, want_expl,
                             f"baseline_{n}.json disagrees on the "
                             f"exploratory scorable set")

    def test_exploratory_block_is_separate_and_reconciled(self):
        rep = json.loads((BASE / "baseline_majority.json")
                         .read_text(encoding="utf-8"))
        expl = rep["families_exploratory"]
        self.assertEqual(sorted(expl), [
            "F_false_positive_rejection.jsonl", "G_patch_verification.jsonl",
            "I_verified_non_exploit.jsonl", "J_verified_patch.jsonl",
        ])
        self.assertFalse(set(rep["families"]) & set(expl),
                         "exploratory families leaked into the headline set")
        self.assertEqual(rep["micro_exploratory"]["scorable"],
                         sum(s["scorable"] for s in expl.values()))
        for fam, stats in expl.items():
            for base in (BENCH, VBENCH):
                p = base / fam
                if p.is_file():
                    self.assertEqual(stats["scorable"], _labeled(p), fam)
                    break
            else:
                self.fail(f"{fam}: no benchmark file found")

    def test_retired_block_is_per_family_and_reconciled(self):
        rep = json.loads((BASE / "baseline_majority.json")
                         .read_text(encoding="utf-8"))
        ret = rep["families_retired"]
        self.assertEqual(rep["micro_retired"]["scorable"],
                         sum(s["scorable"] for s in ret.values()))
        self.assertFalse(set(rep["families"]) & set(ret))
        for fam, stats in ret.items():
            p = BENCH / "retired_families" / fam
            self.assertTrue(p.is_file(), f"{fam}: no retired file")
            self.assertEqual(stats["scorable"], _labeled(p), fam)

    def test_scopes_reconcile_to_all_families(self):
        """The four family blocks partition every scored family.

        The report has four blocks -- primary, exploratory, invalid and
        retired -- plus the all-families continuity twin. The reconciliation
        is computed from the report's own fields: each block must equal the
        sum of the families it names, and the four blocks must sum to the
        twin. No number is typed in, so the check follows the data.
        """
        blocks = (("micro", "families"),
                  ("micro_exploratory", "families_exploratory"),
                  ("micro_invalid", "families_invalid"),
                  ("micro_retired", "families_retired"))
        for n in ("majority", "random_seed7", "frequency_seed7",
                  "first_published", "majority_published", "retrieval"):
            rep = json.loads((BASE / f"baseline_{n}.json")
                             .read_text(encoding="utf-8"))
            for micro, fams in blocks:
                self.assertEqual(
                    rep[micro]["scorable"],
                    sum(s["scorable"] for s in rep[fams].values()),
                    f"baseline_{n}.json: {micro} != the sum of {fams}")
            parts = sum(rep[micro]["scorable"] for micro, _f in blocks)
            self.assertEqual(parts, rep["micro_all_families"]["scorable"],
                             f"baseline_{n}.json: primary + exploratory + "
                             f"invalid + retired != all families")


if __name__ == "__main__":
    unittest.main(verbosity=2)