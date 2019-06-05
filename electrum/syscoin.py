#!/usr/bin/env python
#
# Electrum-SYS - lightweight Syscoin client
# Copyright (C) 2018 Namecoin Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import struct

from electrum.script import ScriptPubKey, OpCodes, _match_ops, Script, ScriptError, OP_1
from hashlib import sha256


def double_sha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))


OP_RETURN = OpCodes.OP_RETURN
HASHX_LEN = 11


class Syscoin:

    BASIC_HEADER_SIZE = 80

    # alias service
    OP_ALIAS_ACTIVATE = 0x01
    OP_ALIAS_UPDATE = 0x02

    # offer service
    OP_OFFER_ACTIVATE = 0x01
    OP_OFFER_UPDATE = 0x02

    # cert service
    OP_CERT_ACTIVATE = 0x01
    OP_CERT_UPDATE = 0x02
    OP_CERT_TRANSFER = 0x03

    # escrow service
    OP_ESCROW_ACTIVATE = 0x01
    OP_ESCROW_RELEASE = 0x02
    OP_ESCROW_REFUND = 0x03
    OP_ESCROW_REFUND_COMPLETE = 0x04
    OP_ESCROW_RELEASE_COMPLETE = 0x05
    OP_ESCROW_BID = 0x06
    OP_ESCROW_ACKNOWLEDGE = 0x07
    OP_ESCROW_ADD_SHIPPING = 0x08
    OP_ESCROW_FEEDBACK = 0x09

    # asset service
    OP_ASSET_ACTIVATE = 0x01
    OP_ASSET_UPDATE = 0x02
    OP_ASSET_TRANSFER = 0x03
    OP_ASSET_SEND = 0x04
    OP_ASSET_COLLECT_INTEREST = 0x02
    OP_ASSETA_SEND = 0x01

    # service ops
    OP_SYSCOIN_ALIAS = 0x01
    OP_SYSCOIN_CERT = 0x02
    OP_SYSCOIN_ESCROW = 0x03
    OP_SYSCOIN_OFFER = 0x04
    OP_SYSCOIN_ASSET = 0x05
    OP_SYSCOIN_ASSETA = 0x06

    SYSCOIN_TX_VERSION = 0x7400

    # Opcode sequences for alias operations
    ALIAS_NEW_O = [OP_1 + OP_SYSCOIN_ALIAS - 1, OP_1 + OP_ALIAS_ACTIVATE - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    ALIAS_ACTIVATE_O = [OP_1 + OP_SYSCOIN_ALIAS - 1, OP_1 + OP_ALIAS_ACTIVATE - 1, -1, -1, -1, -1,
                        OpCodes.OP_2DROP, OpCodes.OP_2DROP, OpCodes.OP_2DROP]
    ALIAS_UPDATE_O = [OP_1 + OP_SYSCOIN_ALIAS - 1, OP_1 + OP_ALIAS_UPDATE - 1, -1, -1, -1, -1,
                      OpCodes.OP_2DROP, OpCodes.OP_2DROP, OpCodes.OP_2DROP]

    # Opcode sequences for asset operations
    ASSET_ACTIVATE_O = [OP_1 + OP_SYSCOIN_ASSET - 1, OP_1 + OP_ASSET_ACTIVATE - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    ASSET_UPDATE_O = [OP_1 + OP_SYSCOIN_ASSET - 1, OP_1 + OP_ASSET_UPDATE - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    ASSET_TRANSFER_O = [OP_1 + OP_SYSCOIN_ASSET - 1, OP_1 + OP_ASSET_TRANSFER - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    ASSET_SEND_O = [OP_1 + OP_SYSCOIN_ASSET - 1, OP_1 + OP_ASSET_SEND - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    ASSETA_SEND_O = [OP_1 + OP_SYSCOIN_ASSETA - 1, OP_1 + OP_ASSETA_SEND - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]

    # Opcode sequences for offer operations
    OFFER_ACTIVATE_O = [OP_1 + OP_SYSCOIN_OFFER - 1, OP_1 + OP_OFFER_ACTIVATE - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    OFFER_UPDATE_O = [OP_1 + OP_SYSCOIN_OFFER - 1, OP_1 + OP_OFFER_UPDATE - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]

    # Opcode sequences for certificate operations
    CERT_ACTIVATE_O = [OP_1 + OP_SYSCOIN_CERT - 1, OP_1 + OP_CERT_ACTIVATE - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    CERT_UPDATE_O = [OP_1 + OP_SYSCOIN_CERT - 1, OP_1 + OP_CERT_UPDATE - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]
    CERT_TRANSFER_O = [OP_1 + OP_SYSCOIN_CERT - 1, OP_1 + OP_CERT_TRANSFER - 1, -1, OpCodes.OP_2DROP, OpCodes.OP_DROP]

    OP_RETURN_DATA_O = [OP_RETURN, -1]

    @classmethod
    def get_dropcode_count(cls, op_def):
        if len(op_def) == 5:
            return 2
        else:
            return 3

    # array of ops that we are looking for
    syscoin_ops_def = [
        ALIAS_NEW_O, ALIAS_ACTIVATE_O, ALIAS_UPDATE_O,
        ASSET_ACTIVATE_O, ASSET_UPDATE_O, ASSET_TRANSFER_O, ASSET_SEND_O, ASSETA_SEND_O,
        OFFER_ACTIVATE_O, OFFER_UPDATE_O,
        CERT_ACTIVATE_O, CERT_UPDATE_O, CERT_TRANSFER_O,
        OP_RETURN_DATA_O
    ]
    syscoin_alias_ops_def = [ALIAS_NEW_O, ALIAS_ACTIVATE_O, ALIAS_UPDATE_O]
    syscoin_offer_ops_def = [OFFER_ACTIVATE_O, OFFER_UPDATE_O]
    syscoin_cert_ops_def = [CERT_ACTIVATE_O, CERT_UPDATE_O, CERT_TRANSFER_O]
    syscoin_asset_ops_def = [ASSET_ACTIVATE_O, ASSET_UPDATE_O, ASSET_TRANSFER_O, ASSET_SEND_O, ASSETA_SEND_O]

    @classmethod
    def get_script_type(cls, script):
        try:
            ops = Script.get_ops(script)
        except ScriptError:
            return None, script

        match = _match_ops

        for el in cls.syscoin_alias_ops_def:
            if match(ops[:len(el)], el):
                return "ALIAS"
        for el in cls.syscoin_offer_ops_def:
            if match(ops[:len(el)], el):
                return "OFFER"
        for el in cls.syscoin_cert_ops_def:
            if match(ops[:len(el)], el):
                return "CERT"
        for el in cls.syscoin_asset_ops_def:
            if match(ops[:len(el)], el):
                return "ASSET"
        return None

    @classmethod
    def script_to_bytes(cls, ops):
        bytea = bytearray()
        for op in ops:
            if op is not None:
                if isinstance(op, tuple):
                    for j in op:
                        if j is not None:
                            if isinstance(j, bytes):
                                bytea.extend(j)
                            else:
                                bytea.append(j)
                        else:
                            bytea.append(0)
                else:
                    bytea.append(op)
            else:
                bytea.append(0)
        return bytes(bytea)

    @classmethod
    def split_syscoin_script(cls, script, get_ops=True):
        if get_ops is True:
            try:
                ops = Script.get_ops(script)
            except ScriptError:
                return None, script
        else:
            ops = script

        match = _match_ops
        script_pushdata = matching_opdef = None

        # conveniently, all the above syscoin ops have the same format - syscoin op, service op, data, 2DROP, DROP
        # the following if statement matches the script stack against a list of syscoin script templates. if one
        # matches it means we have found a syscoin transaction and need to to further processing to extract the
        # address script from the script
        for el in cls.syscoin_ops_def:
            if match(ops[:len(el)], el):
                matching_opdef = el
                script_pushdata = ops[2:len(el)-cls.get_dropcode_count(matching_opdef)]
                break

        # if op_type is None then this isn't a Syscoin transaction and we can bail
        if matching_opdef is None:
            return None, script

        # Find the end position of the name data
        n = len(matching_opdef)

        # Strip the syscoin data to yield the address script
        address_script = script[n:]

        if script_pushdata is None:
            return None, address_script

        sys_script_out = ops[:n]
        return sys_script_out, address_script

    @classmethod
    def hashX_from_script(cls, script):
        sys_op_script, address_script = cls.split_syscoin_script(script)
        if address_script and address_script[0] == OP_RETURN:
            return None
        return sha256(cls.script_to_bytes(address_script)).digest()[:HASHX_LEN]

    @classmethod
    def sys_hashX_from_script(cls, script):
        sys_op_script, address_script = cls.split_syscoin_script(script)
        if sys_op_script and sys_op_script[0] == OP_RETURN:
            return None
        return sha256(cls.script_to_bytes(sys_op_script)).digest()[:HASHX_LEN]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])
