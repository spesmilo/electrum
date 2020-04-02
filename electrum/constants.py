# -*- coding: utf-8 -*-
#
# ElectrumSys - lightweight Bitcoin client
# Copyright (C) 2018 The ElectrumSys developers
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

import os
import json

from .util import inv_dict
from . import bitcoin


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r


GIT_REPO_URL = "https://github.com/syscoin/electrumsys"
GIT_REPO_ISSUES_URL = "https://github.com/syscoin/electrumsys/issues"

class AbstractNet:
    FEE_ETA_TARGETS = [25, 10, 5, 2]
    FEE_DEPTH_TARGETS = [10000000, 5000000, 2000000, 1000000, 500000, 200000, 100000]
    FEE_LN_ETA_TARGET = 2  # note: make sure the network is asking for estimates for this target

    # satoshi per kbyte
    FEERATE_MAX_DYNAMIC = 1500000
    FEERATE_WARNING_HIGH_FEE = 600000
    FEERATE_FALLBACK_STATIC_FEE = 150000
    FEERATE_DEFAULT_RELAY = 1000
    FEERATE_MAX_RELAY = 50000
    FEERATE_STATIC_VALUES = [1000, 2000, 5000, 10000, 20000, 30000,
                            50000, 70000, 100000, 150000, 200000, 300000]
    FEERATE_REGTEST_HARDCODED = 180000  # for eclair compat
    AUXPOW_CHAIN_ID = 0x0001
    POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60  # 2 weeks
    POW_TARGET_SPACING = 10 * 60  # 600 seconds
    POW_BLOCK_ADJUST = int(POW_TARGET_TIMESPAN / POW_TARGET_SPACING) # 2016
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 0
    AUXPOW_START_HEIGHT = 0
    @classmethod
    def max_checkpoint(cls) -> int:
        return max(0, len(cls.CHECKPOINTS) * net.POW_BLOCK_ADJUST - 1)

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(bitcoin.rev_hex(cls.GENESIS))


class BitcoinMainnet(AbstractNet):

    TESTNET = False
    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    SEGWIT_HRP = "bc"
    GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    CHECKPOINTS = read_json('checkpoints.json', [])
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 497000

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh':  0x0295b005,  # Yprv
        'p2wpkh':      0x04b2430c,  # zprv
        'p2wsh':       0x02aa7a99,  # Zprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh':  0x0295b43f,  # Ypub
        'p2wpkh':      0x04b24746,  # zpub
        'p2wsh':       0x02aa7ed3,  # Zpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 0
    LN_REALM_BYTE = 0
    LN_DNS_SEEDS = [
        'nodes.lightning.directory.',
        'lseed.bitcoinstats.com.',
    ]


class BitcoinTestnet(AbstractNet):

    TESTNET = True
    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    SEGWIT_HRP = "tb"
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = read_json('checkpoints_testnet.json', [])

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh':  0x024285b5,  # Uprv
        'p2wpkh':      0x045f18bc,  # vprv
        'p2wsh':       0x02575048,  # Vprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh':  0x024289ef,  # Upub
        'p2wpkh':      0x045f1cf6,  # vpub
        'p2wsh':       0x02575483,  # Vpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 1
    LN_REALM_BYTE = 1
    LN_DNS_SEEDS = [  # TODO investigate this again
        #'test.nodes.lightning.directory.',  # times out.
        #'lseed.bitcoinstats.com.',  # ignores REALM byte and returns mainnet peers...
    ]


class BitcoinRegtest(BitcoinTestnet):

    SEGWIT_HRP = "bcrt"
    GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []
    LN_DNS_SEEDS = []


class BitcoinSimnet(BitcoinTestnet):

    WIF_PREFIX = 0x64
    ADDRTYPE_P2PKH = 0x3f
    ADDRTYPE_P2SH = 0x7b
    SEGWIT_HRP = "sb"
    GENESIS = "683e86bd5c6d110d91b94b97137ba6bfe02dbbdb8e3dff722a669b5d69d77af6"
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []
    LN_DNS_SEEDS = []

class AbstractSyscoinNet:
    FEE_ETA_TARGETS = [25, 10, 5, 2]
    FEE_DEPTH_TARGETS = [10000000, 5000000, 2000000, 1000000, 500000, 200000, 100000]
    FEE_LN_ETA_TARGET = 2  # note: make sure the network is asking for estimates for this target

    # satoshi per kbyte
    FEERATE_MAX_DYNAMIC = 15000000
    FEERATE_WARNING_HIGH_FEE = 6000000
    FEERATE_FALLBACK_STATIC_FEE = 1500000
    FEERATE_DEFAULT_RELAY = 10000
    FEERATE_MAX_RELAY = 500000
    FEERATE_STATIC_VALUES = [10000, 20000, 50000, 100000, 200000, 300000,
                            500000, 700000, 1000000, 1500000, 2000000, 3000000]
    FEERATE_REGTEST_HARDCODED = 1800000  # for eclair compat
    AUXPOW_CHAIN_ID = 0x1000
    POW_TARGET_TIMESPAN = 6 * 60 * 60  #  6 hours
    POW_TARGET_SPACING = 60  # 60 seconds
    POW_BLOCK_ADJUST = int(POW_TARGET_TIMESPAN / POW_TARGET_SPACING)
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 0

    @classmethod
    def max_checkpoint(cls) -> int:
        return max(0, len(cls.CHECKPOINTS) * net.POW_BLOCK_ADJUST - 1)

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(bitcoin.rev_hex(cls.GENESIS))


class SyscoinMainnet(AbstractSyscoinNet):

    TESTNET = False
    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = 0x3f
    ADDRTYPE_P2SH = 0x05
    SEGWIT_HRP = "sys"
    GENESIS = "0000022642db0346b6e01c2a397471f4f12e65d4f4251ec96c1f85367a61a7ab"
    DEFAULT_PORTS = {'s': '58882'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    CHECKPOINTS = read_json('checkpoints.json', [])
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 497000

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh':  0x0295b005,  # Yprv
        'p2wpkh':      0x04b2430c,  # zprv
        'p2wsh':       0x02aa7a99,  # Zprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh':  0x0295b43f,  # Ypub
        'p2wpkh':      0x04b24746,  # zpub
        'p2wsh':       0x02aa7ed3,  # Zpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 57
    LN_REALM_BYTE = 0
    LN_DNS_SEEDS = [
        'nodes.lightning.directory.',
        'lseed.bitcoinstats.com.',
    ]

    AUXPOW_CHAIN_ID = 0x1000
    AUXPOW_START_HEIGHT = 1973
    nBridgeStartBlock = 348000


class SyscoinTestnet(AbstractSyscoinNet):

    TESTNET = True
    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 0x41
    ADDRTYPE_P2SH = 0xc4
    SEGWIT_HRP = "tsys"
    GENESIS = "0000064430008f1fe74ba0bf54080f1cf6e73da3372df7617e33648529940fc3"
    DEFAULT_PORTS = {'t': '59991', 's': '59992'}
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = read_json('checkpoints_testnet.json', [])

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh':  0x024285b5,  # Uprv
        'p2wpkh':      0x045f18bc,  # vprv
        'p2wsh':       0x02575048,  # Vprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh':  0x024289ef,  # Upub
        'p2wpkh':      0x045f1cf6,  # vpub
        'p2wsh':       0x02575483,  # Vpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 1
    LN_REALM_BYTE = 1
    LN_DNS_SEEDS = [  # TODO investigate this again
        #'test.nodes.lightning.directory.',  # times out.
        #'lseed.bitcoinstats.com.',  # ignores REALM byte and returns mainnet peers...
    ]


class SyscoinRegtest(SyscoinTestnet):

    SEGWIT_HRP = "scrt"
    GENESIS = "28a2c2d251f46fac05ade79085cbcb2ae4ec67ea24f1f1c7b40a348c00521194"
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []
    LN_DNS_SEEDS = []
    AUXPOW_CHAIN_ID = 0x1000


class SyscoinSimnet(SyscoinTestnet):

    WIF_PREFIX = 0x64
    ADDRTYPE_P2PKH = 0x3f
    ADDRTYPE_P2SH = 0x7b
    SEGWIT_HRP = "sb"
    GENESIS = "683e86bd5c6d110d91b94b97137ba6bfe02dbbdb8e3dff722a669b5d69d77af6"
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []
    LN_DNS_SEEDS = []


# don't import net directly, import the module instead (so that net is singleton)
net = SyscoinMainnet

def set_simnet():
    global net
    net = BitcoinSimnet

def set_mainnet():
    global net
    net = BitcoinMainnet

def set_testnet():
    global net
    net = BitcoinTestnet


def set_regtest():
    global net
    net = BitcoinRegtest
