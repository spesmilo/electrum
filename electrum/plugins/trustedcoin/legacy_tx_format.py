# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import copy
from typing import Union

from electrum import bitcoin
from electrum.bitcoin import push_script, int_to_hex, var_int
from electrum.transaction import (Transaction, PartialTransaction, PartialTxInput,
                                  multisig_script, construct_witness)
from electrum.keystore import BIP32_KeyStore
from electrum.wallet import Multisig_Wallet


ELECTRUM_PARTIAL_TXN_HEADER_MAGIC = b'EPTF\xff'
PARTIAL_FORMAT_VERSION = b'\x00'
NO_SIGNATURE = b'\xff'


def get_xpubkey(keystore: BIP32_KeyStore, c, i) -> str:
    def encode_path_int(path_int) -> str:
        if path_int < 0xffff:
            hex = bitcoin.int_to_hex(path_int, 2)
        else:
            hex = 'ffff' + bitcoin.int_to_hex(path_int, 4)
        return hex

    s = ''.join(map(encode_path_int, (c, i)))
    return 'ff' + bitcoin.DecodeBase58Check(keystore.xpub).hex() + s


def serialize_tx_in_legacy_format(tx: PartialTransaction, *, wallet: Multisig_Wallet) -> str:
    assert isinstance(tx, PartialTransaction)

    def get_siglist(txin: 'PartialTxInput', *, estimate_size=False):
        if txin.prevout.is_coinbase():
            return [], []
        if estimate_size:
            try:
                pubkey_size = len(txin.pubkeys[0])
            except IndexError:
                pubkey_size = 33  # guess it is compressed
            num_pubkeys = max(1, len(txin.pubkeys))
            pk_list = ["00" * pubkey_size] * num_pubkeys
            # we assume that signature will be 0x48 bytes long
            num_sig = max(txin.num_sig, num_pubkeys)
            sig_list = [ "00" * 0x48 ] * num_sig
        else:
            pk_list = ["" for pk in txin.pubkeys]
            for ks in wallet.get_keystores():
                my_pubkey, full_path = ks.find_my_pubkey_in_txinout(txin)
                x_pubkey = get_xpubkey(ks, full_path[-2], full_path[-1])
                pubkey_index = txin.pubkeys.index(my_pubkey)
                pk_list[pubkey_index] = x_pubkey
            assert all(pk_list)
            sig_list = [txin.part_sigs.get(pubkey, NO_SIGNATURE).hex() for pubkey in txin.pubkeys]
        return pk_list, sig_list

    def input_script(self, txin: PartialTxInput, *, estimate_size=False) -> str:
        assert estimate_size is False
        pubkeys, sig_list = get_siglist(txin, estimate_size=estimate_size)
        script = ''.join(push_script(x) for x in sig_list)
        if txin.script_type == 'p2sh':
            # put op_0 before script
            script = '00' + script
            redeem_script = multisig_script(pubkeys, txin.num_sig)
            script += push_script(redeem_script)
            return script
        elif txin.script_type == 'p2wsh':
            return ''
        raise Exception(f"unexpected type {txin.script_type}")
    tx.input_script = input_script.__get__(tx, PartialTransaction)

    def serialize_witness(self, txin: PartialTxInput, *, estimate_size=False):
        assert estimate_size is False
        if txin.witness is not None:
            return txin.witness.hex()
        if txin.prevout.is_coinbase():
            return ''
        assert isinstance(txin, PartialTxInput)
        if not self.is_segwit_input(txin):
            return '00'
        pubkeys, sig_list = get_siglist(txin, estimate_size=estimate_size)
        if txin.script_type == 'p2wsh':
            witness_script = multisig_script(pubkeys, txin.num_sig)
            witness = construct_witness([0] + sig_list + [witness_script])
        else:
            raise Exception(f"unexpected type {txin.script_type}")
        if txin.is_complete() or estimate_size:
            partial_format_witness_prefix = ''
        else:
            input_value = int_to_hex(txin.value_sats(), 8)
            witness_version = int_to_hex(0, 2)
            partial_format_witness_prefix = var_int(0xffffffff) + input_value + witness_version
        return partial_format_witness_prefix + witness
    tx.serialize_witness = serialize_witness.__get__(tx, PartialTransaction)

    buf = ELECTRUM_PARTIAL_TXN_HEADER_MAGIC.hex()
    buf += PARTIAL_FORMAT_VERSION.hex()
    buf += tx.serialize_to_network()
    return buf
