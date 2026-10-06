# V3 experiment queue (prioritized)

Target discipline: same attack sequence against vulnerable AND fixed revisions (L6 bar).
Toolchains absent here (Sui/Aptos/Scarb/Clarinet/forc/Stellar) are marked environment_blocked, not failed.

## Priority 1: defihacklabs:src/test/2017-07/Parity_first_hack_exp
Finding: Incident reproduction PoC: Parity_first_hack_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 2: defihacklabs:src/test/2017-11/Parity_kill_exp
Finding: Incident reproduction PoC: Parity_kill_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 3: defihacklabs:src/test/2018-04/BEC_exp
Finding: Incident reproduction PoC: BEC_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 4: defihacklabs:src/test/2018-04/SmartMesh_exp
Finding: Incident reproduction PoC: SmartMesh_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 5: defihacklabs:src/test/2018-10/SpankChain_exp
Finding: Incident reproduction PoC: SpankChain_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 6: defihacklabs:src/test/2020-04/LendfMe_exp
Finding: Incident reproduction PoC: LendfMe_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 7: defihacklabs:src/test/2020-06/Balancer_20200628_exp
Finding: Incident reproduction PoC: Balancer_20200628_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 8: defihacklabs:src/test/2020-06/Bancor_exp
Finding: Incident reproduction PoC: Bancor_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 9: defihacklabs:src/test/2020-08/Opyn_exp
Finding: Incident reproduction PoC: Opyn_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 10: defihacklabs:src/test/2020-09/bzx_exp
Finding: Incident reproduction PoC: bzx_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 11: defihacklabs:src/test/2020-10/HarvestFinance_exp
Finding: Incident reproduction PoC: HarvestFinance_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 12: defihacklabs:src/test/2020-11/Pickle_exp
Finding: Incident reproduction PoC: Pickle_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 13: defihacklabs:src/test/2020-12/Cover_exp
Finding: Incident reproduction PoC: Cover_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 14: defihacklabs:src/test/2021-01/Sushi_Badger_Digg_exp
Finding: Incident reproduction PoC: Sushi_Badger_Digg_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 15: defihacklabs:src/test/2021-02/Yearn_ydai_exp
Finding: Incident reproduction PoC: Yearn_ydai_exp
Reason: published PoC + quality 30; cheapest path to L4/L5
Required environment: foundry/forge (EVM)
Vulnerable commit: unknown
Fixed commit: unknown
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L5

## Priority 16: pashov-audits:team/1inch-security-review:[L-01]
Finding: Unverified integratorFee Within Reasonable Range
Reason: exact review commit + severity Low; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 198a6d719aef8b6cd0b29e18a128f4abcf978046
Fixed commit: 8c19fb95792c8fec76ed8f11554300dc0056416d
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 17: pashov-audits:team/1inch-security-review:[L-02]
Finding: Limitation of `timeDelta` to Around 18 Hours Due to 16-bit Encoding
Reason: exact review commit + severity Low; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 198a6d719aef8b6cd0b29e18a128f4abcf978046
Fixed commit: 8c19fb95792c8fec76ed8f11554300dc0056416d
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 18: pashov-audits:team/1inch-security-review:[L-03]
Finding: Unverified timeDelta Leading to Transaction Panic
Reason: exact review commit + severity Low; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 198a6d719aef8b6cd0b29e18a128f4abcf978046
Fixed commit: 8c19fb95792c8fec76ed8f11554300dc0056416d
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 19: pashov-audits:team/1inch-security-review:[L-04]
Finding: Whitelist Extension cannot handle the case when there is no whitelist
Reason: exact review commit + severity Low; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 198a6d719aef8b6cd0b29e18a128f4abcf978046
Fixed commit: 8c19fb95792c8fec76ed8f11554300dc0056416d
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 20: pashov-audits:team/1inch-security-review:[M-01]
Finding: FeeTaker is not accounting for `unwrapWeth` Feature
Reason: exact review commit + severity Medium; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 198a6d719aef8b6cd0b29e18a128f4abcf978046
Fixed commit: 8c19fb95792c8fec76ed8f11554300dc0056416d
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 21: pashov-audits:team/1inch-security-review:[M-02]
Finding: FeeTaker is incompatible with fee-on-transfer tokens
Reason: exact review commit + severity Medium; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 198a6d719aef8b6cd0b29e18a128f4abcf978046
Fixed commit: 8c19fb95792c8fec76ed8f11554300dc0056416d
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 22: pashov-audits:team/GainsNetwork-security-review-July:[H-01]
Finding: Storage slot collision
Reason: exact review commit + severity High; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 9847881d77ebacdf0824b3440a65e8ed1ac52cbc
Fixed commit: e0f440b2cdddcdbe9022df6414717700906de45c
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 23: pashov-audits:team/GainsNetwork-security-review-July:[M-01]
Finding: `MIN_GNS_WEI_IN` is too small leading to zero rewards
Reason: exact review commit + severity Medium; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 9847881d77ebacdf0824b3440a65e8ed1ac52cbc
Fixed commit: e0f440b2cdddcdbe9022df6414717700906de45c
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 24: pashov-audits:team/SXT-security-review_2025-03-31:[C-02]
Finding: Emptying ETH from `ZKPay.sol`
Reason: exact review commit + severity Critical; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 73462f93d03a0cae29129db62b75615f96639c93
Fixed commit: ffa98911b034c8b976a3830ff93938c7710efce7
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

## Priority 25: pashov-audits:team/SXT-security-review_2025-03-31:[L-01]
Finding: No gas limit safeguard allows gas draining
Reason: exact review commit + severity Low; reconstruct PoC from finding text
Required environment: per-report toolchain (see source dossier)
Vulnerable commit: 73462f93d03a0cae29129db62b75615f96639c93
Fixed commit: ffa98911b034c8b976a3830ff93938c7710efce7
Expected violation: as claimed in source (reported_claim until observed)
Verification target: L6

