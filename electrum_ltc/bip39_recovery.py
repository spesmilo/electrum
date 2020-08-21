# Copyright (C) 2020 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import TYPE_CHECKING

from aiorpcx import TaskGroup

from . import bitcoin
from .constants import BIP39_WALLET_FORMATS
from .bip32 import BIP32_PRIME, BIP32Node
from .bip32 import convert_bip32_path_to_list_of_uint32 as bip32_str_to_ints
from .bip32 import convert_bip32_intpath_to_strpath as bip32_ints_to_str

if TYPE_CHECKING:
    from .network import Network


async def account_discovery(network: 'Network', get_account_xpub):
    async with TaskGroup() as group:
        account_scan_tasks = []
        for wallet_format in BIP39_WALLET_FORMATS:
            account_scan = scan_for_active_accounts(network, get_account_xpub, wallet_format)
            account_scan_tasks.append(await group.spawn(account_scan))
    active_accounts = []
    for task in account_scan_tasks:
        active_accounts.extend(task.result())
    return active_accounts


async def scan_for_active_accounts(network: 'Network', get_account_xpub, wallet_format):
    active_accounts = []
    account_path = bip32_str_to_ints(wallet_format["derivation_path"])
    while True:
        account_xpub = get_account_xpub(account_path)
        account_node = BIP32Node.from_xkey(account_xpub)
        has_history = await account_has_history(network, account_node, wallet_format["script_type"])
        if has_history:
            account = format_account(wallet_format, account_path)
            active_accounts.append(account)
        if not has_history or not wallet_format["iterate_accounts"]:
            break
        account_path[-1] = account_path[-1] + 1
    return active_accounts


async def account_has_history(network: 'Network', account_node: BIP32Node, script_type: str) -> bool:
    gap_limit = 20
    async with TaskGroup() as group:
        get_history_tasks = []
        for address_index in range(gap_limit):
            address_node = account_node.subkey_at_public_derivation("0/" + str(address_index))
            pubkey = address_node.eckey.get_public_key_hex()
            address = bitcoin.pubkey_to_address(script_type, pubkey)
            script = bitcoin.address_to_script(address)
            scripthash = bitcoin.script_to_scripthash(script)
            get_history = network.get_history_for_scripthash(scripthash)
            get_history_tasks.append(await group.spawn(get_history))
    for task in get_history_tasks:
        history = task.result()
        if len(history) > 0:
            return True
    return False


def format_account(wallet_format, account_path):
    description = wallet_format["description"]
    if wallet_format["iterate_accounts"]:
        account_index = account_path[-1] % BIP32_PRIME
        description = f'{description} (Account {account_index})'
    return {
        "description": description,
        "derivation_path": bip32_ints_to_str(account_path),
        "script_type": wallet_format["script_type"],
    }
