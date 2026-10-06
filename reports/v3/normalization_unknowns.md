# V3.1 unknown audit

Every still-unknown field: how many, which sources, and what evidence would resolve it.

## severity_normalized: unknown = 0
by_source: {}
resolving evidence: explicit Severity field in the finding segment

## normalized_vulnerability_classes: unknown = 4944
by_source: {'abdk-audits': 2589, 'anza-security-audits': 12, 'certora-reports': 16, 'cyba-audits': 23, 'nethermind-audits': 613, 'sigmaprime-audits': 636, 'zellic-publications': 1055}
resolving evidence: explicit auditor Category/Type label

## language: unknown = 3622
by_source: {'abdk-audits': 2088, 'anza-security-audits': 21, 'certora-reports': 14, 'nethermind-audits': 698, 'sigmaprime-audits': 421, 'zellic-publications': 380}
resolving evidence: README platform column or explicit framework + file-extension convergence

## ecosystem: unknown = 3997
by_source: {'abdk-audits': 2088, 'anza-security-audits': 21, 'certora-reports': 14, 'nethermind-audits': 698, 'sigmaprime-audits': 421, 'zellic-publications': 755}
resolving evidence: explicit platform/repository evidence (Rust alone insufficient)

## affected_file_candidates: unknown = 4377
by_source: {'abdk-audits': 2129, 'anza-security-audits': 14, 'certora-reports': 2, 'cyba-audits': 1, 'nethermind-audits': 698, 'sigmaprime-audits': 109, 'zellic-publications': 1424}
resolving evidence: code filename or blob permalink in the finding segment

## affected_function_reported: unknown = 7037
by_source: {'abdk-audits': 2872, 'anza-security-audits': 22, 'certora-reports': 21, 'cyba-audits': 44, 'nethermind-audits': 708, 'sigmaprime-audits': 1081, 'zellic-publications': 2289}
resolving evidence: explicit Function field or attributed signature

## commit_shas: unknown = 7018
by_source: {'abdk-audits': 2872, 'anza-security-audits': 22, 'certora-reports': 21, 'cyba-audits': 44, 'nethermind-audits': 706, 'sigmaprime-audits': 1079, 'zellic-publications': 2274}
resolving evidence: 40-hex SHA in scope/fix context

## poc_section: unknown = 7007
by_source: {'abdk-audits': 2872, 'anza-security-audits': 22, 'certora-reports': 15, 'cyba-audits': 32, 'nethermind-audits': 708, 'sigmaprime-audits': 1081, 'zellic-publications': 2277}
resolving evidence: PoC/proof section with code in the finding segment

## fix_status_reported: unknown = 2359
by_source: {'abdk-audits': 47, 'anza-security-audits': 22, 'certora-reports': 1, 'zellic-publications': 2289}
resolving evidence: explicit Status field in the finding segment

## V3.0 baseline (context, not rewritten)
{'severity': 2995, 'language': 1072, 'ecosystem': 1044}
