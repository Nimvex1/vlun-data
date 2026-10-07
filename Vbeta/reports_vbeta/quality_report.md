# Vbeta quality report

Dataset version vbeta-1.0. Isolated layer: no PRESENT file touched (see present_snapshot.json).

## Sources (zero overlap with V3's 18)

- cantina-portfolio: candidates=6 langs=solidity tier=2 receipt=https://cantina.xyz/portfolio
- cyfrin-codehawks: candidates=8 langs=solidity tier=2 receipt=https://github.com/Cyfrin/2023-07-foundry-defi-stablecoin/blob/main/audits/codehawks-08-05-2023.md
- immunefi-past-competitions: candidates=2 langs=solidity tier=2 receipt=https://github.com/immunefi-team/Past-Audit-Competitions
- movebit-sampled-audits: candidates=15 langs=move tier=1 receipt=https://github.com/movebit/Sampled-Audit-Reports
- neodyme-reports: candidates=12 langs=rust tier=1 receipt=https://neodyme.io/reports/
- openzeppelin-cairo: candidates=2 langs=cairo tier=1 receipt=https://github.com/OpenZeppelin/cairo-contracts
- ottersec-audits: candidates=11 langs=rust,move,solidity tier=1 receipt=https://osec.io/audits
- runtime-verification-publications: candidates=3 langs=rust tier=1 receipt=https://github.com/runtimeverification/publications
- shieldify-audits-portfolio: candidates=33 langs=solidity,rust,move,go tier=1 receipt=https://github.com/shieldify-security/audits-portfolio
- solodit-harvest: candidates=733 langs=solidity,unknown tier=2 receipt=https://solodit.cyfrin.io/
- trailofbits-publications: candidates=4 langs=cairo,rust,solidity tier=1 receipt=https://github.com/trailofbits/publications
- veridise-zk-archive: candidates=15 langs=circom,noir,leo,cairo,rust,solidity,go tier=1 receipt=https://veridise.com/audits-archive/zero-knowledge-security/

## Findings

candidates=844 admitted_records=719
decisions={'CORROBORATION_ONLY': 63, 'IMPORT': 60, 'IMPORT_AS_NEGATIVE': 5, 'IMPORT_AS_UNVERIFIED': 654, 'RESEARCH_ONLY': 62}

## Verification

levels={'L0': 787, 'L1': 57}
L2-L6: 0 by construction (nothing executed in this pass).

## Languages / ecosystems (admitted records)

{'cairo': 2, 'go': 23, 'move': 20, 'rust': 14, 'solidity': 560, 'unknown': 95, 'vyper': 5}
{'aptos': 10, 'cosmos': 9, 'evm': 567, 'solana': 7, 'starknet': 2, 'sui': 7, 'unknown': 117}

## Honest exclusions

- blocksec: only a CTF fork repo found; queued, not faked.
- clarity/sway depth: no finding-level material observed; queued.
- 62 RESEARCH_ONLY pointers: counts/titles observed, no per-finding severity — kept as pointers, never upgraded.

## Licensing

METADATA_ONLY everywhere; openzeppelin-cairo rows carry observed MIT.
