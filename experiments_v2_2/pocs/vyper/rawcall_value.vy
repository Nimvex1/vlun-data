# VLUN v2.2 verification PoC - claim GHSA-x2c2-q32w-4w6m
# Claim under test: the compiler does not reject `value=` on a delegate call, so
# `raw_call(..., is_delegate_call=True, value=...)` compiles without error and the
# value argument is silently ignored at runtime.
# Claim source: https://github.com/vyperlang/vyper/security/advisories/GHSA-x2c2-q32w-4w6m
# Written from the published claim for reproduction purposes; not a copy of any
# upstream repository file.

@external
@payable
def send_value(to: address, data: Bytes[256]) -> Bytes[255]:
    return raw_call(to, data, max_outsize=255, is_delegate_call=True,
                    value=msg.value)
