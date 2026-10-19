# responses/ — empty by design

This directory is where completed annotation files go. **It is empty: no human has
annotated anything as of 2026-10-19, so no agreement has been measured.**

Rules the directory enforces (see `scripts/iaa_statistics.py`):

- one file per annotator: `annotator_1.csv`, `annotator_2.csv`, `annotator_3.csv`, copied
  from `annotation/iaa_v1/blank/annotator_N.template.csv`;
- `annotator_kind` must literally be `human`. Files whose rows are all `llm`,
  `self_consistency`, `model`, `agent` or `automated` are excluded from the statistic and
  the exclusion is reported — LLM self-consistency is never presented as inter-annotator
  agreement;
- `annotator_id` must be distinct per person: two passes by one id are self-consistency,
  and the script refuses to call it IAA;
- `.template.csv` files are ignored by the reader, which is why the shipped blanks are
  named `*.template.csv`;
- do not hand-edit a completed file after the statistic is generated: supersede it as
  `annotator_1.v2.csv` and record why in the disagreement log.

A run with real responses produces `reports/iaa_status.json` with `measured: true`, one
`per_pair` block per annotator pair (Cohen's κ on the primary root-cause label, linear and
quadratic weighted κ on severity tier and evidence ceiling) and a `pooled` block with
Krippendorff's α plus percentile bootstrap CIs. Until that file changes, the study is
protocol-only.
