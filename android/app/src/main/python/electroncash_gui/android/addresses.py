from functools import partial
from org.electroncash.electroncash3 import R


def get_addresses(wallet, type, status):
    result = []
    if type != R.id.filterChange:
        result += filter_addresses(wallet, wallet.get_receiving_addresses(), status)
    if type != R.id.filterReceiving:
        result += filter_addresses(wallet, wallet.get_change_addresses(), status)
    return result


def filter_addresses(wallet, addresses, status):
    return filter(partial(FILTERS[status], wallet), addresses)


FILTERS = {
    R.id.filterAll:
        lambda wallet, addr: True,
    R.id.filterUsed:
        lambda wallet, addr: (wallet.get_address_history(addr) and
                              not wallet.get_addr_balance(addr)[0]),
    R.id.filterFunded:
        lambda wallet, addr: wallet.get_addr_balance(addr)[0],
    R.id.filterUnused:
        lambda wallet, addr: not wallet.get_address_history(addr),
}
