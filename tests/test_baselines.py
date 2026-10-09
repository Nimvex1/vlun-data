"""Guard: published baseline reports must match the shipped benchmark files.

The committed baselines were computed against a stale Vbeta population
(624/719 scorable rows) while the shipped Vbeta benchmark files carry
6,218/6,935. A stale floor is worse than no floor: a model result read
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
        want = None
        for n in ("majority", "random_seed7", "frequency_seed7",
                  "first_published", "majority_published", "retrieval"):
            p = BASE / f"baseline_{n}.json"
            rep = json.loads(p.read_text(encoding="utf-8"))
            s = rep["micro"]["scorable"]
            if want is None:
                want = s
            self.assertEqual(s, want, f"baseline_{n}.json disagrees on "
                                      f"the scorable task set")


if __name__ == "__main__":
    unittest.main(verbosity=2)