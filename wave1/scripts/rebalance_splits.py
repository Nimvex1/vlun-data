"""Deterministic per-label stratified re-split of judge families F/Fa/Fb.

Restores the governed 70/15/15 ratio where the row count permits it, and
enforces the >=30 validation / >=30 test floor otherwise (small families use
35/30/30 because 70/15/15 cannot satisfy the floor with <200 rows).

Writes only wave1/benchmark_wave1/F*.jsonl. Stdlib only, idempotent.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from _common import WAVE1, guard_wave1, read_jsonl, sha256_text, write_jsonl, write_json

FAMILIES = [
    "F_false_positive_rejection",
    "Fa_rejection_evidence_axis_vector",
    "Fb_duplicate_radar_pair",
]


def assign(n: int, total: int, fam: str = "") -> str:
    # Fb must satisfy train>=40, val>=30, test>=30 with as few as 100 rows.
    if fam == "Fb_duplicate_radar_pair":
        tr, va = 40, 30
    elif total < 200:
        tr, va = 35, 30
    else:
        tr, va = 70, 15
    cut_train = total * tr // 100
    cut_val = cut_train + total * va // 100
    if n < cut_train:
        return "train"
    if n < cut_val:
        return "val"
    return "test"


def main() -> None:
    summary = {}
    for fam in FAMILIES:
        p = WAVE1 / "benchmark_wave1" / f"{fam}.jsonl"
        rows = list(read_jsonl(p))
        if not rows:
            summary[fam] = {"rows": 0}
            continue
        # group by label, then order deterministically inside each label
        by_label: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            by_label[str(r.get("label"))].append(r)
        out = []
        for label, group in sorted(by_label.items()):
            group.sort(key=lambda r: sha256_text(
                str(r.get("repo_slug") or "") + "|" + str(r.get("candidate_id") or r.get("task_id"))
            ))
            for i, r in enumerate(group):
                r = dict(r)
                r["split"] = assign(i, len(group), fam)
                out.append(r)
        out.sort(key=lambda r: (str(r.get("split")), str(r.get("label")), str(r.get("task_id"))))
        write_jsonl(guard_wave1(p), out)
        splits = Counter(str(r.get("split")) for r in out)
        per_split_labels = defaultdict(set)
        for r in out:
            per_split_labels[str(r.get("split"))].add(str(r.get("label")))
        summary[fam] = {
            "rows": len(out),
            "splits": dict(sorted(splits.items())),
            "labels_per_split": {k: sorted(v) for k, v in sorted(per_split_labels.items())},
            "ratio": "35/30/30 (floor-preserving; <200 rows)" if len(out) < 200 else "70/15/15",
        }
        print(f"[{fam}] {len(out)} rows {dict(sorted(splits.items()))} "
              f"labels/split={summary[fam]['labels_per_split']}")
    write_json(WAVE1 / "reports_wave1" / "split_rebalance.json", summary)


if __name__ == "__main__":
    main()
