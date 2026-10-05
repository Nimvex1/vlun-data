# VLUN v2.2 verification PoC - claim GHSA-6j9c-gvcw-74fj
# Claim under test (published 2026-10-02, source: GitHub repository advisory):
#   with optimization on (-O gas, the default, or -O codesize), `(msg.value | K)`
#   used as a branch of a ternary expression compiles to the constant 1 whatever
#   amount was sent; -O none produces the correct value.
#   f(True) with msg.value = 5 returns 1 at the default level and 7 at -O none.
# Claim source: https://github.com/vyperlang/vyper/security/advisories/GHSA-6j9c-gvcw-74fj
# This contract was written from the published claim in order to reproduce it.
# It is not a copy of any upstream repository file, and nothing else from the
# advisory's prose is reproduced here (the advisory carries no licence statement).

@external
@payable
def calc(flag: bool) -> uint256:
    return (msg.value | 2) if flag else 5
