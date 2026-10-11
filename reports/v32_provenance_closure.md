# V3.2 provenance closure

Independent reproduction of the two L5 exploit claims, and closure of the
stale-hash defect found during the benchmark-validity audit. Nothing below
is inferred from compilation alone; every number was read off a run or a
byte comparison.

## 1. Root cause

The same artefact hash is recorded in three places. Commit `c124c7e`
recomputed the hashes "from disk — 34/34 verify" after the CRLF/LF
platform defect, but only rewrote one copy:

| copy | reader | hashes matched disk? |
|---|---|---|
| `experiments_v3/*/result.json` | `tests/test_artefact_hashes.py` | yes (the only copy tested) |
| `reports/v3/experimental_proof.json` | `scripts/v32_execution.py` | **no — all 6 runs stale** |
| `jsonl_v3/findings.jsonl` + `derived_v3/records.jsonl` | every consumer | **no — inherited the stale copy** |

The existing test `test_proof_runs_have_full_artefact_set` checked that the
files *existed*, never that the hashes *matched*. So the canonical record
files carried L5 provenance pointers that did not hash to the bytes they
claimed to prove. The evidence itself (attacker-profit logs) was never in
doubt; the pointer was broken.

## 2. Affected records

All 6 proof runs in `reports/v3/experimental_proof.json`:

| run | level | status | stale hashes |
|---|---|---|---|
| pikefinance | L5 | violation_observed | 4 of 5 |
| swappstaking | L5 | violation_observed | 4 of 5 |
| burgerswap | L3 | blocked (`archive_state_unavailable`) | 5 of 5 |
| shibatoken | L3 | blocked (`archive_state_unavailable`) | 5 of 5 |
| gamma | L3 | blocked (`archive_state_unavailable`) | 5 of 5 |
| prisma | L3 | blocked (`archive_state_unavailable`) | 4 of 5 |

27 hash values corrected in total. The 4 blocked L3s keep
`status=blocked`, `failure_reason=archive_state_unavailable` — failures
remain failures; nothing was upgraded.

## 3. Independent verification of the corrections

Three independent methods, none of which is the tool that made the fix:

1. **OS-native hashing** (`Get-FileHash`, PowerShell): 30/30 proof hashes
   and 60/60 record-file hashes match the bytes on disk. 0 mismatches.
2. **New unit tests** (`tests/test_artefact_hashes.py`): `result.json`,
   proof-level and record-level hashes all recomputed with `hashlib`
   directly — 8/8 pass, including a negative control (an injected bad hash
   fails the suite).
3. **Structural diff** (HEAD vs worktree): 27 hash values changed in each
   of the three files; every non-hash field — level, status, basis,
   failure_reason, finding_id, compile evidence, profit evidence — is
   byte-identical. Semantic changes: NONE.

All three copies now agree with each other and with disk (6/6 runs).

## 4. Reproduction results

Clean checkouts of `https://github.com/SunWeb3Sec/DeFiHackLabs` at the
pinned commit `0200ce8a...47fa29` (verified `rev-parse HEAD`, clean tree),
PoC bytes verified against the recorded `poc_sha256` before running,
isolated per-PoC staging mirroring the original pipeline (the full checkout
does not compile — unrelated broken files, documented below). Toolchain
`forge 1.8.3 (cae51ad)`, solc 0.8.37, pinned forge-std `3353993`. Public
RPC `https://eth-mainnet.public.blastapi.io`; both PoCs pin their fork
block in-source.

**PikeFinance — REPRODUCED (PASS).** `forge test --match-test testExploit -vv`,
rc=0. Attacker ETH `0.0 → 479.393838338750964434`, matching the recorded
`479.393838338751` to display precision. The violated invariant is
conservation of value through the oracle path: the exploit leaves the
attacker ~479.39 ETH richer with no corresponding deposit.

**SWAPPStaking — REPRODUCED (PASS).** Same command, rc=0. Attacker
`0 → 128657759164064`, staking contract `128657759164064 → 0`, exactly
matching the recorded deltas including the counterparty leg. This is the
pair the instructions require: attacker-side gain *plus* the corresponding
depletion, not compilation and not an unchanged balance.

Run outputs (stdout sha256 `b919d3c1…` / `7da37ec8…`, stderr empty both
runs) are recorded in the working notes, not committed — committing
re-run logs would create a fourth copy of this evidence to drift.

Two honest deltas from the original runs: gas differs slightly (Pike
117,956 vs 120,655; SWAPP 3,877,487 vs 3,905,140), consistent with a
different solc build than the original run used; profit figures are
identical. Verdict criterion was profit, not gas.

## 5. Changed files

- `reports/v3/experimental_proof.json` — 27 stale hashes recomputed, nothing else
- `jsonl_v3/findings.jsonl` — 27 inherited hashes corrected, nothing else
- `derived_v3/records.jsonl` — 27 inherited hashes corrected, nothing else
- `scripts/reconcile_proof_artefact_hashes.py` — new; recomputes from disk,
  `--check` fails on any stale or missing hash across all three copies
- `scripts/run_gates.py` — new `proof-hashes-current` gate (network-free),
  registered under `--only proof`. Fixing the registration exposed two
  adjacent defects: the gate ran in no group so the full suite skipped it
  (17/17 while GATES held 18), and `--only` crashed with `KeyError` on any
  subset. Both fixed; full suite is now 18/18.
- `tests/test_artefact_hashes.py` — `test_proof_hashes_match_disk`,
  `test_record_hashes_match_disk` (both with negative-control verification)

No severity, status, evidence, level or admission label was changed.

## 6. Residual risks

1. **The full DeFiHackLabs checkout at the pinned commit does not compile**
   (unrelated PoCs reference a missing `src/interface.sol`, a missing
   balancer import, and a unicode literal solc rejects). Reproduction
   requires the isolated staging the pipeline already uses. Anyone running
   the recorded command in a full checkout gets a compiler error, not an
   exploit result.
2. **Fork RPC is a live dependency.** Both reproductions fetched pinned-block
   state from a public endpoint. If the endpoint dies or rate-limits, the
   runs fail with no local fallback; the committed artefacts are then the
   only evidence, which is exactly what the hash invariant now protects.
3. **Gas is not pinned.** Same forge, possibly different solc than the
   original run; gas differs ~2%. Profit — the L5 criterion — is identical.
4. **E (1 labeled row) and D (generative, no judge) remain unevaluable.**
   This closure fixes provenance for 6 records; it does not create
   reproduction evidence at scale, and the audit's verdict on those
   families stands.
5. **The re-run logs live outside the repo.** Their hashes are quoted in §4;
   the bytes are not committed. If the working notes are lost, the runs
   must be repeated — which the pinned revisions make possible.
