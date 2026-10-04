# 2025-06-panoptic/H-01 — single-revision PoC run

- verdict: `reproduced` — The materialised PoC asserts the FINDING's claimed outcome. forge reported Success, so the claimed outcome was observed at the audited commit.
- forge status: `Success`
- test: `test_submissionValidity`
- repository: `code-423n4/2025-06-panoptic` at commit `eea2c931b1cbce1da01586e42ba298814de40d31`
- PoC type: `repo_native_test` — The audit author's own test, run unmodified from the audited repository. This reproduces the reporter's claim; it is not an exploit constructed by this dataset.
- body committed: **no** — The PoC body is not redistributed. verify_pocs.py restores the audited test tree after each run, so the materialised body is not recoverable; for repo_native_test rows it is unlicensed upstream source. Reconstruct it from poc_materialised_file / poc_native_location at audited_commit, or from the code quoted in the public report.
- fixed-revision leg: **no** — This is a single-revision run at the audited commit. It is NOT one of the pinpoint vulnerable-vs-fixed experiments in experiments/<finding>__*/{vulnerable,fixed}/ and does not establish that a patch was effective.

Full record: [`result.json`](result.json)
