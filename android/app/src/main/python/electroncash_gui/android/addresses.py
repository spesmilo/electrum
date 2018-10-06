from functools import partial


def get_addresses(wallet):
    addrs = wallet.get_addresses()
    addrs.sort(key=partial(addr_type, wallet))
    return addrs


# See <string-array name="address_type">
def addr_type(wallet, addr):
    return (0 if addr == wallet.get_unused_address() else
            1 if not wallet.is_change(addr) else
            2)
