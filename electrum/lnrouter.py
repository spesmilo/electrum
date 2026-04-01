def fee_for_edge_msat(forwarded_amount_msat: int, fee_base_msat: int, fee_proportional_millionths: int) -> int:
    if forwarded_amount_msat < 0 or fee_base_msat < 0 or fee_proportional_millionths < 0:
        raise ValueError('Amount and fees cannot be negative')
    if forwarded_amount_msat > 2**31 - 1 or fee_base_msat > 2**31 - 1 or fee_proportional_millionths > 2**31 - 1:
        raise ValueError('Amount and fees exceed maximum allowed value')
    return fee_base_msat + (forwarded_amount_msat * fee_proportional_millionths // 1_000_000)