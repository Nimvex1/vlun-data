# Phase 6 — derived-chain citation stage & IAA gate subprocess

Two failures from the final pytest run. Both are resolved without weakening a
check, inventing a pin, or changing a dataset. Python stdlib only.

## Ownership / scope

Changed:

- `tests/test_reproducibility_parity.py` — stale chain assertion.
- `tests/test_taxonomy_gate.py` — Windows subprocess isolation in the `run()` helper.
- this report.

Explicitly NOT touched: `scripts/check_reproducibility.py` (`DERIVED_CHAIN` was
already correct), `scripts/iaa_statistics.py` (no logic defect), datasets, other
tests, gate scripts, builders, or fixtures.

## Failure 4 — `test_chain_includes_the_citation_resolution_stage`

Observed:

```
AssertionError: 'scripts/resolve_citations.py' not found in
['scripts/build_derived.py', 'scripts/replay_v1_citation_pins.py',
 'scripts/build_derived.py', 'scripts/build_derived.py']
```

Root cause: the **test was stale**, not the chain. Phase 5 deliberately replaced
`resolve_citations.py` with `replay_v1_citation_pins.py` in `DERIVED_CHAIN`
(`reports/phase5_fixes_repro.md`, "Fix 1") and updated the checker's own
documentation, but did not update this test. The resolver reads only git-ignored
clones (`work/wt`, `work/repos`, `work/sources`, `work/source_manifest.json`)
that a partial checkout does not have; its own write-guard correctly refuses the
run rather than shrink the authoritative 639 immutable pins to the ~553 the
remaining clones can resolve. Re-adding it to the chain would make the gate fail
reproducibility (non-zero rc), so that was not an option.

Fix: the test now asserts that the chain contains
`scripts/replay_v1_citation_pins.py` — the offline stage that re-applies the
published pin set verbatim and is the citation-resolution stage used to publish
the committed layer — and additionally asserts that `resolve_citations.py` is
**not** in the chain, so a future "fix" cannot silently reintroduce a shrinking
stage. The module docstring was updated to match. The test's intent (citation
resolution is a stage of the derived chain) is preserved; no check was relaxed.

## Failure 5 — IAA report "LLM self-consistency as human" rejected

Observed in the final run: `iaa_statistics.py` exited `3221225786`, i.e.
`0xC000013A = STATUS_CONTROL_C_EXIT`, with empty stdout and stderr.

Investigation:

- `python scripts/iaa_statistics.py` -> exit 0, `wrote ... iaa_status.json (measured=False)`.
- `python -m pytest -q tests/test_taxonomy_gate.py::IAAGuessesAreRejected -v` -> `2 passed in 0.23s`.
- Direct reproduction of the exact failing invocation (`--audit-report` on
  `iaa_report_llm_as_iaa.json`, `--responses` with two `llm_self_consistency`
  rows) -> `returncode=1`, stderr:
  `report claims measured agreement over 2 rows, none of them annotated as human; LLM self-consistency is not inter-annotator agreement`
  plus `all annotator kinds are non-human (llm_self_consistency)`.

So the script has no logic defect and the gate's exit-1/stderr contract holds.
The failure did not reproduce in isolation. `0xC000013A` is a Windows console
control-C termination: with several test runs sharing one console, a Ctrl+C
aimed at another run is delivered to every process in that console group,
including this test's child, which dies before Python can print a reason.

Fix: the shared `run()` helper now launches each child with
`creationflags=subprocess.CREATE_NEW_PROCESS_GROUP` on Windows (`0` on other
platforms). A new process group disables CTRL+C for the child, isolating the
gate subprocess from unrelated interrupts. Both assertions are unchanged — the
test still requires exit code 1 and the word `self-consistency` on stderr. This
fixes the harness invocation, not the script's behaviour.

## Verification

```
python scripts/check_reproducibility.py --quiet
    -> exit 0; checks=19 pass=17 fail=0 skipped=2

python -m pytest -q tests/test_reproducibility_parity.py tests/test_taxonomy_gate.py
    -> exit 0; 38 passed, 2 subtests passed in 3.85s
       (baseline before the fixes: 1 failed, 37 passed, 2 subtests passed)

python -m ruff check tests/test_reproducibility_parity.py tests/test_taxonomy_gate.py
    -> All checks passed!
```

The 2 skips are the pre-existing honest `skipped_no_network` stages; no skip
was added and no verdict logic changed. `git diff --stat` over the generated
reports (`iaa_status.json`, `reproducibility_checks{,_summary}.json`) is empty:
running the checks left those artefacts byte-identical.
