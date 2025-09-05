from typing import TYPE_CHECKING, List

from electrum.simple_config import ConfigVar, SimpleConfig
from electrum.commands import plugin_command

if TYPE_CHECKING:
    from electrum.commands import Commands
    from electrum.wallet import Abstract_Wallet


plugin_name = "swapserver"


SimpleConfig.SWAPSERVER_PORT = ConfigVar('plugins.swapserver.port', default=None, type_=int, plugin=__name__)
SimpleConfig.SWAPSERVER_FEE_MILLIONTHS = ConfigVar('plugins.swapserver.fee_millionths', default=5000, type_=int, plugin=__name__)
SimpleConfig.SWAPSERVER_ANN_POW_NONCE = ConfigVar('plugins.swapserver.ann_pow_nonce', default=0, type_=int, plugin=__name__)


@plugin_command('wl', plugin_name)
async def get_history(self: 'Commands', wallet: 'Abstract_Wallet' = None, plugin = None) -> List[dict]:
    """
    Get a list of all swaps provided by this swapserver.
    Single elements can potentially cover multiple swaps if transactions have been batched.

    Example result:

        [
            {
                "date": "2025-09-04",
                "label": "Forward swap 0.2018 mBTC",
                "timestamp": 1756982141,  # unix timestamp
                "return_sat": -205  # value in satoshi that has been earned or lost with this swap
            },
            {
                "date": "2025-09-04",
                "label": "Reverse swap 0.30406 mBTC",
                "timestamp": 1756983236,
                "return_sat": 64
            }
        ]
    """
    assert wallet.lnworker, "lightning not available"
    assert wallet.lnworker.swap_manager, "swap manager not available"

    full_history = wallet.get_full_history()
    swap_group_ids = set(
        x['group_id'] for x in wallet.lnworker.swap_manager.get_groups_for_onchain_history().values()
    )

    swap_history_items = []
    for swap_group_id in swap_group_ids:
        if swap_history_item := full_history.get('group:' + swap_group_id):
            swap_history_items.append(swap_history_item)

    result = []
    for swap in swap_history_items:
        result.append({
            'label': swap['label'],
            'return_sat': int(swap['value'].value),
            'date': swap['date'].strftime("%Y-%m-%d"),
            'timestamp': swap['timestamp']
        })
    result = sorted(result, key=lambda x: x['timestamp'])
    return result


@plugin_command('wl', plugin_name)
async def get_summary(self: 'Commands', wallet: 'Abstract_Wallet' = None, plugin = None) -> dict:
    """Get a summary of all swaps provided by this swapserver.
    Can become incorrect if closed lightning channels have been deleted in this wallet.

    Example result:
    {
        "num_swaps": 160,
        "overall_return_sat": 159052,  # value earned or lost in satoshi
        "swaps_per_day": 0.78  # between first swap and last swap
    }
    """
    swap_history = await get_history(self)
    profit_loss_sum = sum(swap['return_sat'] for swap in swap_history) if swap_history else 0
    first_swap = min(swap['timestamp'] for swap in swap_history) if swap_history else 0
    last_swap = max(swap['timestamp'] for swap in swap_history) if swap_history else 0
    days_in_operation = (last_swap - first_swap) // 86400
    swaps_per_day = (len(swap_history) / days_in_operation) if days_in_operation > 0 else 0

    return {
        'num_swaps': len(swap_history),
        'overall_return_sat': profit_loss_sum,
        'swaps_per_day': round(swaps_per_day, 2),
    }
