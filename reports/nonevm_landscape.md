# How this non-EVM pilot compares with published projects

Written for spec item 9. The purpose of this file is to stop a claim being
made that the data cannot support: **this pilot is not "the only multi-VM
executed security corpus in existence".** Executable security corpora exist,
several of them with per-finding proof-of-concept code, and at least one
project covers multiple execution environments with mandatory exploit and
patch execution. What follows is what each linked project actually contains,
as read from its own page on 2026-10-19, and then what this pilot can and
cannot claim.

Method: web search for benchmark / dataset / corpus projects that (a) cover a
non-EVM or multi-VM target, or (b) publish executed proof-of-concept exploits;
then the project's own repository or paper page was read for scope, artefact
type and whether execution is part of the deliverable. Figures are quoted as
reported by the source; re-verify before citing them.

## Adjacent public projects, by artefact type

| Project | Target(s) | What ships | Executed per finding? | Source |
|---|---|---|---|---|
| SmartBugs / SB-Curated | Solidity, EVM | curated vulnerable contracts with ground-truth annotations, plus a framework for running analysis tools over them | tool runs, not incident PoCs | [smartbugs-curated](https://github.com/smartbugs/smartbugs-curated), [SmartBugs framework](https://joaoff.com/2020/03/05/smartbugs-an-execution-framework-for-automated-analysis-of-smart-contracts/) |
| SolidiFI | Solidity, EVM | systematically *injected* bugs with labels for detector evaluation | synthetic injection, labelled code | [cited in an attack-centric taxonomy survey](https://arxiv.org/html/2511.09051) |
| PoPoC | Solidity, EVM | ~100+ exploit PoCs extracted from real audit reports, reproducible with Foundry/Docker; a thesis describes the extraction and validation method | yes, executable PoCs | [ASSERT-KTH/PoPoC](https://github.com/ASSERT-KTH/PoPoC), [benchmark thesis (PDF)](https://www.diva-portal.org/smash/get/diva2:2046583/FULLTEXT01.pdf) |
| PoCo | Solidity, EVM | agentic generation of executable Foundry PoCs from natural-language findings, plus a public proof-of-patch dataset and trajectory viewer | yes, generated and executed | [arXiv:2511.02780](https://arxiv.org/html/2511.02780v3), [PoCo-public](https://github.com/ASSERT-KTH/PoCo-public) |
| EVMbench | EVM | an agent benchmark of real audit/exploit tasks with proof-of-exploit and proof-of-patch execution requirements (~35 tasks as reported) | yes, execution is the grading signal | [EVMbench paper (PDF)](https://cdn.openai.com/evmbench/evmbench.pdf) |
| SARMF-Bench | Solidity | small reproducible vulnerability benchmark released as a dataset | reproducible harness, not a breadth claim | [researchsquare preprint (PDF)](https://www.researchsquare.com/article/rs-9161109/v1.pdf), [Mendeley data](https://data.mendeley.com/datasets/kd3vcpnn9v/1) |
| DeFiHackLabs | EVM | runnable fork tests reproducing real attacks (this repository ingests it as a source) | yes, on forked local nodes | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) (mirrored locally under `work/sources/DeFiHackLabs/`) |
| Solodit, Code4rena, Sherlock, Cantina, LisaBench | mostly Solidity/EVM; the contest platforms also host Move, Rust, Cairo and CosmWasm contests | finding text and severity, sometimes PoC snippets | prose first; execution is not the shipped artefact | [crawl script in this repo](../../scripts/crawl_solodit.py); [LisaBench links recorded in `Vbeta/`](../../Vbeta/lisabench_candidates.json) |
| GHSA / OSV / RustSec / `CosmWasm/advisories` | all ecosystems | advisory text, affected ranges, patch commits, CVSS | no PoC execution | [CWA-2024-002 as fetched for this repo](../../work/v2_2/raw/rust/CWA-2024-002.md) |
| Move-ecosystem research: MoveScanner, MoveEVM classification, empirical studies | Sui / Aptos Move | labelled contract corpora, detector studies, vulnerability taxonomies | static analysis over published contracts | [arXiv:2508.17964](https://arxiv.org/html/2508.17964v3), [arXiv:2505.19047](https://arxiv.org/html/2505.19047v1), [empirical study](https://www.semanticscholar.org/paper/Empirical-Study-of-Move-Smart-Contract-Security%3A-Song-Chen/4db6daa1261af2a990fbf09c4590f2d243856bd9) |
| awesome-move-security | Sui/Aptos Move | curated links to audits, tools, research | index, not data | [Monethic/awesome-move-security](https://github.com/Monethic/awesome-move-security) |

Two observations that matter for the claim under test:

1. **Executable PoC corpora already exist, and they are not small.** PoPoC
   ships on the order of a hundred verified Solidity exploit PoCs; PoCo
   generates and runs them; EVMbench grades agents by executing an exploit
   and a patch. Any statement that this repository is the only project with
   executed proof-of-concepts is false.
2. **Coverage of non-EVM VMs with *executed* evidence is genuinely thinner
   than EVM coverage.** That is a real gap, and it is why this pilot exists -
   but "thinner" is not "absent". Upstream projects themselves publish the
   decisive executed artefacts: the integer-mate PR #7 fix carries the Move
   tests that reject the boundary call; the cosmwasm patch commits referenced
   by CWA-2024-002 add Rust regression tests; the OpenZeppelin Cairo
   advisories ship with a fixed release whose suite runs. Those are
   per-repository regression tests rather than a cross-VM dataset, which is
   exactly the difference this pilot sits in - and it is not a difference in
   kind.

## What this pilot can claim

* A **pinned, per-assertion, cross-VM execution pilot** on four non-EVM
  toolchains already present on this host, in which each recorded run names
  the assertion it evaluated, hashes its own stdout/stderr, and states which
  revision it tested and how that pin was resolved.
* **L5 reproductions on pinned upstream revisions** (not reconstructions):
  the Sui Move `checked_shlw` truncation reproduces on the audited v1.1.0
  revision and, for the boundary value, on the incomplete PR #6 fix; the
  `cosmwasm-std` arithmetic wrap reproduces on the versions the advisory
  declares affected, including the advisory's own scoping condition on
  `overflow-checks`.
* **L6 shape at record level** where the same named test both reproduces on
  one pin and is refused on the patched pin - computed from the artefacts,
  not asserted.
* **Prerequisite and blocker data as a first-class result**: the Aptos CLI and
  the Anchor/Solana CLIs are absent, the Scarb available here cannot build the
  Cairo revisions the candidates name, and several Sui candidates pin a
  framework revision that is not in the local dependency cache. Each is
  recorded with the command that clears it.
* A safety posture that is stated and verifiable: local package test runners
  only (`sui move test`, `scarb cairo-test`, `cargo test`), scratch copies of
  read-only clones, no node, no fork, no faucet, no deployment, no funds.

## What this pilot cannot claim

* It is **not a corpus of 30-50 completed executions.** The v2.2 pool of
  non-EVM candidates is 30 records across the four platforms; the number of
  executions this pilot actually completed is whatever `reports/nonevm_pilot.json`
  recomputes from `experiments_nonevm/`, and the rest are blockers.
* It does **not cover the EVM-bench-style evidence class**: no forked-mainnet
  exploit replay, no transaction-level state transition, no real incident
  reproduction. Chain-level candidates (Sui node CVEs, wasmvm sandbox escape,
  a live-market accumulator bug) stay blocked here.
* It does **not include the 156 non-Solidity records that `Vbeta/` references
  through contest links**: their upstream commits are unknown, so a pin cannot
  be resolved, and the V3/Vbeta layers are metadata-only - their prose and
  code are not copied into any artefact of this pilot.
* It is **single-host, single-toolchain-generation** evidence. A different
  Scarb/Sui/cargo vintage changes which revisions are buildable, so the
  `toolchain.txt` of each run is part of the result rather than boilerplate.
* Licence review is **partial**: the executed third-party trees here are MIT
  (integer-mate) or MIT/Apache (cairo-contracts, cosmwasm-std) and no upstream
  file is copied into a distribution artefact, but nothing in this pilot has
  been cleared for the *published* dataset layer; `WITHHELD.json` is not needed
  because no restricted source entered an artefact, and that judgement is per
  record, not global.

## Reading order

1. `reports/nonevm_pilot.md` - counts, prerequisite matrix, outcomes, blockers.
2. `experiments_nonevm/<record_id>/<run>/result.json` - one execution: pin,
   runtime, named assertion, exit code, hashes, ladder level.
3. `scripts/nonevm/*.py` - how each platform resolves prerequisites and
   evaluates assertions.
4. `tests/test_nonevm_pilot.py` - the integrity rules these artefacts are held
   to, including a fixture for every way a run could be overstated.
