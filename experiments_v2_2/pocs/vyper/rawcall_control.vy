# VLUN v2.2 control for GHSA-x2c2-q32w-4w6m
# Same construct as rawcall_value.vy with the `value=` kwarg removed, so that a
# compile error on the value form can be attributed to the value kwarg and not to
# the delegate call itself.

@external
@payable
def send_value(to: address, data: Bytes[256]) -> Bytes[255]:
    return raw_call(to, data, max_outsize=255, is_delegate_call=True)
