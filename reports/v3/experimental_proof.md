# V3.2 experimental proof (measured)

Levels per scripts/poc_classification.py. L6 never awarded here (no fixed revision executed).

runs: 6
by_status: {'blocked': 4, 'violation_observed': 2}
by_level: {'L3': 4, 'L5': 2}

## Compile triage (L3 gate)
compiled: 127/129
failure_reasons: {'Identifier already declared.': 1, 'Invalid character in string. If you are trying to use Unicode characters, use a unicode"..." string ': 1}
failed_files: ['2026-01/PRXVT_exp.sol', '2026-04/SaturnProtocol_exp.sol']
via_ir_builds: ['2026-05/Renegade_exp.sol', '2026-05/VerusBridge_exp.sol']

## Patch verification
47 patch candidates, all not_testable: none has an executable PoC on either revision (0 overlap with PoC-code overlays), so no same-test dual-revision run exists. No L6 claimed.

## defihacklabs:2021-05/BurgerSwap_exp.sol -> blocked (L3)
- fork_aliases: ['bsc']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: [FAIL: EVM error; database error: failed to get account for 0x72b61c6014342d914470eC7aC2975bE345796c2b: server returned an error response: error code -32000: missing trie node] setUp() (gas: 0)
- artifact_dir: C:/Users/REDACTED/Downloads/vlun-data-main/vlun-data-main/experiments_v3/burgerswap
- seconds: 5.1

## defihacklabs:2023-11/ShibaToken_exp.sol -> blocked (L3)
- fork_aliases: ['bsc', 'https://rpc.ankr.com/bsc']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: [FAIL: EVM error; database error: failed to get account for 0x8b6C8fd93d6F4CeA42Bbb345DBc6F0DFdb5bEc73: server returned an error response: error code -32000: missing trie node] setUp() (gas: 0)
- artifact_dir: C:/Users/REDACTED/Downloads/vlun-data-main/vlun-data-main/experiments_v3/shibatoken
- seconds: 3.6

## defihacklabs:2024-01/Gamma_exp.sol -> blocked (L3)
- fork_aliases: ['arbitrum']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: [FAIL: EVM error; database error: failed to get account for 0xA4b000000000000000000073657175656e636572: server returned an error response: error code -32000: historical state f62796e05e4d7f1bf3ebb3220
- artifact_dir: C:/Users/REDACTED/Downloads/vlun-data-main/vlun-data-main/experiments_v3/gamma
- seconds: 3.3

## defihacklabs:2024-03/Prisma_exp.sol -> blocked (L3)
- fork_aliases: ['mainnet']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: [FAIL: vm.createSelectFork: backend: failed replaying transaction; transaction validation error: gas floor (21680) exceeds the gas limit (21438)] setUp() (gas: 0)
- artifact_dir: C:/Users/REDACTED/Downloads/vlun-data-main/vlun-data-main/experiments_v3/prisma
- seconds: 163.9

## defihacklabs:2024-04/PikeFinance_exp.sol -> violation_observed (L5)
- fork_aliases: ['mainnet']
- level_basis: attacker profit > 0 observed in balance logs on fork: theft mechanics demonstrated
- profit_deltas: [{'label_before': 'Attacker ETH Balance Before exploit', 'label_after': 'Attacker ETH Balance After exploit', 'before': 0.0, 'after': 479.393838338751, 'profit': 479.393838338751, 'attacker_side': True}]
- artifact_dir: C:/Users/REDACTED/Downloads/vlun-data-main/vlun-data-main/experiments_v3/pikefinance
- seconds: 7.9

## defihacklabs:2025-07/SWAPPStaking_exp.sol -> violation_observed (L5)
- fork_aliases: ['mainnet']
- level_basis: attacker profit > 0 observed in balance logs on fork: theft mechanics demonstrated
- profit_deltas: [{'label_before': 'current balance of attacker', 'label_after': 'balance of attacker after exploiting', 'before': 0.0, 'after': 128657759164064.0, 'profit': 128657759164064.0, 'attacker_side': True}, {'label_before': 'current balance of staking', 'label_after': 'balance of staking after exploiting', 'before': 128657759164064.0, 'after': 0.0, 'profit': -128657759164064.0, 'attacker_side': False}]
- artifact_dir: C:/Users/REDACTED/Downloads/vlun-data-main/vlun-data-main/experiments_v3/swappstaking
- seconds: 48.4

