# V3.2 experimental proof (measured)

Levels per scripts/poc_classification.py. L6 never awarded here (no fixed revision executed).

runs: 18
by_status: {'blocked': 5, 'violation_observed': 5, 'executed_no_profit_evidence': 7, 'test_failed': 1}
by_level: {'L3': 6, 'L5': 5, 'L4': 7}

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
- artifact_dir: experiments_v3/burgerswap
- seconds: 5.1

## defihacklabs:2023-11/ShibaToken_exp.sol -> blocked (L3)
- fork_aliases: ['bsc', 'https://rpc.ankr.com/bsc']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: [FAIL: EVM error; database error: failed to get account for 0x8b6C8fd93d6F4CeA42Bbb345DBc6F0DFdb5bEc73: server returned an error response: error code -32000: missing trie node] setUp() (gas: 0)
- artifact_dir: experiments_v3/shibatoken
- seconds: 3.6

## defihacklabs:2024-01/Gamma_exp.sol -> blocked (L3)
- fork_aliases: ['arbitrum']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: [FAIL: EVM error; database error: failed to get account for 0xA4b000000000000000000073657175656e636572: server returned an error response: error code -32000: historical state f62796e05e4d7f1bf3ebb3220
- artifact_dir: experiments_v3/gamma
- seconds: 3.3

## defihacklabs:2024-03/Prisma_exp.sol -> blocked (L3)
- fork_aliases: ['mainnet']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: [FAIL: vm.createSelectFork: backend: failed replaying transaction; transaction validation error: gas floor (21680) exceeds the gas limit (21438)] setUp() (gas: 0)
- artifact_dir: experiments_v3/prisma
- seconds: 163.9

## defihacklabs:2024-04/PikeFinance_exp.sol -> violation_observed (L5)
- fork_aliases: ['mainnet']
- level_basis: attacker profit > 0 observed in balance logs on fork: theft mechanics demonstrated
- profit_deltas: [{'after': 479.393838338751, 'attacker_side': True, 'before': 0.0, 'label_after': 'Attacker ETH Balance After exploit', 'label_before': 'Attacker ETH Balance Before exploit', 'profit': 479.393838338751}]
- artifact_dir: experiments_v3/pikefinance
- seconds: 7.9

## defihacklabs:2025-07/SWAPPStaking_exp.sol -> violation_observed (L5)
- fork_aliases: ['mainnet']
- level_basis: attacker profit > 0 observed in balance logs on fork: theft mechanics demonstrated
- profit_deltas: [{'after': 128657759164064.0, 'attacker_side': True, 'before': 0.0, 'label_after': 'balance of attacker after exploiting', 'label_before': 'current balance of attacker', 'profit': 128657759164064.0}, {'after': 0.0, 'attacker_side': False, 'before': 128657759164064.0, 'label_after': 'balance of staking after exploiting', 'label_before': 'current balance of staking', 'profit': -128657759164064.0}]
- artifact_dir: experiments_v3/swappstaking
- seconds: 48.4

## defihacklabs:2025-08/PresaleV5_exp.sol -> executed_no_profit_evidence (L4)
- fork_aliases: ['mainnet']
- level_basis: forge reported test PASS on pinned fork
- artifact_dir: experiments_v3/presalev5
- seconds: 22.3

## defihacklabs:2026-01/MTToken_exp.sol -> executed_no_profit_evidence (L4)
- fork_aliases: ['bsc']
- level_basis: forge reported test PASS on pinned fork
- artifact_dir: experiments_v3/mttoken
- seconds: 19.0

## defihacklabs:2026-01/futureswap_exp.sol -> blocked (L3)
- fork_aliases: ['arbitrum']
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: archive_state_unavailable
- detail: pinned historical state unservable or unreplayable by the backend
- artifact_dir: experiments_v3/futureswap
- seconds: 5.5

## defihacklabs:2026-03/Venus_THE_exp.sol -> test_failed (L3)
- level_basis: forge build rc=0 on staged PoC (unmodified)
- failure_reason: broken_original_test
- detail: forge test rc!=0 without PASS
- artifact_dir: experiments_v3/venus-the
- seconds: 21.3

## defihacklabs:2026-04/JuiceboxREVLoans_exp.sol -> executed_no_profit_evidence (L4)
- fork_aliases: ['mainnet']
- level_basis: forge reported test PASS on pinned fork
- artifact_dir: experiments_v3/juiceboxrevloans
- seconds: 46.1

## defihacklabs:2026-06/TOPBPool_exp.sol -> executed_no_profit_evidence (L4)
- fork_aliases: ['mainnet']
- level_basis: forge reported test PASS on pinned fork
- profit_deltas: [{'label_before': 'BPool WETH before', 'label_after': 'BPool WETH after', 'before': 944.1954772150741, 'after': 6.93488898486e-07, 'profit': -944.1954765215852, 'attacker_side': False}]
- artifact_dir: experiments_v3/topbpool
- seconds: 27.6

## defihacklabs:2026-08/USM_exp.sol -> violation_observed (L5)
- fork_aliases: ['mainnet']
- level_basis: attacker profit > 0 observed in balance logs on fork: theft mechanics demonstrated
- profit_deltas: [{'after': 70.83097736769771, 'attacker_side': True, 'before': 0.0, 'label_after': 'attacker ETH after (net profit)', 'label_before': 'attacker ETH before', 'profit': 70.83097736769771}]
- artifact_dir: experiments_v3/usm
- seconds: 22.8

## defihacklabs:2026-09/Flamincome_exp.sol -> violation_observed (L5)
- fork_aliases: ['mainnet']
- level_basis: attacker profit > 0 observed in balance logs on fork: theft mechanics demonstrated
- profit_deltas: [{'after': 344751.209366, 'attacker_side': True, 'before': 0.0, 'label_after': 'Attacker After exploit USDT Balance', 'label_before': 'Attacker Before exploit USDT Balance', 'profit': 344751.209366}, {'after': 21836626.905373, 'attacker_side': False, 'before': 3196903.96561, 'label_after': 'Strategy NAV after stakeFor', 'label_before': 'Strategy NAV (balanceOfY) before', 'profit': 18639722.939763}]
- artifact_dir: experiments_v3/flamincome
- seconds: 146.4

## defihacklabs:2026-09/OMNI404_exp.sol -> executed_no_profit_evidence (L4)
- fork_aliases: ['mainnet']
- level_basis: forge reported test PASS on pinned fork
- profit_deltas: [{'after': 0.8683455650399394, 'attacker_side': False, 'before': 3.2953489459416163, 'label_after': 'pool WETH after', 'label_before': 'pool WETH before', 'profit': -2.427003380901677}, {'after': 21.0, 'attacker_side': False, 'before': 15.0, 'label_after': 'O404 minted after', 'label_before': 'O404 minted before', 'profit': 6.0}]
- artifact_dir: experiments_v3/omni404
- seconds: 74.9

## defihacklabs:2026-09/Reddio_exp.sol -> violation_observed (L5)
- fork_aliases: ['mainnet']
- level_basis: attacker profit > 0 observed in balance logs on fork: theft mechanics demonstrated
- profit_deltas: [{'after': 9.263065281137115, 'attacker_side': True, 'before': 0.009975, 'label_after': 'attacker ETH after', 'label_before': 'attacker ETH before', 'profit': 9.253090281137114}]
- artifact_dir: experiments_v3/reddio
- seconds: 29.2

## defihacklabs:2026-09/SecuredFi_exp.sol -> executed_no_profit_evidence (L4)
- fork_aliases: ['mainnet']
- level_basis: forge reported test PASS on pinned fork
- profit_deltas: [{'after': 0.01271959, 'attacker_side': False, 'before': 0.91170963, 'label_after': 'TokenVault WBTC after', 'label_before': 'TokenVault WBTC before', 'profit': -0.89899004}]
- artifact_dir: experiments_v3/securedfi
- seconds: 138.4

## defihacklabs:2026-09/YamFinance_exp.sol -> executed_no_profit_evidence (L4)
- fork_aliases: ['mainnet']
- level_basis: forge reported test PASS on pinned fork
- artifact_dir: experiments_v3/yamfinance
- seconds: 45.9

