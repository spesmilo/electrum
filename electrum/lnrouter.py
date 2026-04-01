def fee_for_edge_msat(forwarded_amount_msat: int, fee_base_msat: int, fee_proportional_millionths: int) -> int:
    if fee_base_msat < 0 or fee_proportional_millionths < 0:
        raise ValueError('Fee base and proportional fee must be non-negative')
    proportional_fee = (forwarded_amount_msat * fee_proportional_millionths) // 1_000_000
    if proportional_fee > 2**31 - 1:
        raise OverflowError('Proportional fee calculation overflow')
    total_fee = fee_base_msat + proportional_fee
    if total_fee > 2**31 - 1:
        raise OverflowError('Total fee calculation overflow')
    return total_fee