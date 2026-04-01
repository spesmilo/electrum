def fee_for_edge_msat(forwarded_amount_msat: int, fee_base_msat: int, fee_proportional_millionths: int) -> int:
    if forwarded_amount_msat < 0 or fee_base_msat < 0 or fee_proportional_millionths < 0:
        raise ValueError('Input values must be non-negative')
    proportional_fee = (forwarded_amount_msat * fee_proportional_millionths + 999999) // 1_000_000
    if proportional_fee > (2**31 - 1) - fee_base_msat:
        raise OverflowError('Integer overflow detected')
    return fee_base_msat + proportional_fee