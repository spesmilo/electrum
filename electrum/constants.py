# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
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
from typing import Sequence, Tuple, Mapping, Type, List, Optional

from .lntransport import LNPeerAddr
from .util import inv_dict, all_subclasses, classproperty
from . import bitcoin


def read_json(filename, default=None):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except Exception:
        if default is None:
            # Sometimes it's better to hard-fail: the file might be missing
            # due to a packaging issue, which might otherwise go unnoticed.
            raise
        r = default
    return r


def create_fallback_node_list(fallback_nodes_dict: dict[str, dict]) -> List[LNPeerAddr]:
    """Take a json dict of fallback nodes like: k:node_id, v:{k:'host', k:'port'} and return LNPeerAddr list"""
    fallback_nodes = []
    for node_id, address in fallback_nodes_dict.items():
        fallback_nodes.append(
            LNPeerAddr(host=address['host'], port=int(address['port']), pubkey=bytes.fromhex(node_id)))
    return fallback_nodes


GIT_REPO_URL = "https://github.com/spesmilo/electrum"
GIT_REPO_ISSUES_URL = "https://github.com/spesmilo/electrum/issues"
BIP39_WALLET_FORMATS = read_json('bip39_wallet_formats.json')


class AbstractNet:

    NET_NAME: str
    TESTNET: bool
    WIF_PREFIX: int
    ADDRTYPE_P2PKH: int
    ADDRTYPE_P2SH: int
    SEGWIT_HRP: str
    BOLT11_HRP: str
    GENESIS: str
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS: int = 0
    BIP44_COIN_TYPE: int
    LN_REALM_BYTE: int
    DEFAULT_PORTS: Mapping[str, str]
    LN_DNS_SEEDS: Sequence[str]
    XPRV_HEADERS: Mapping[str, int]
    XPRV_HEADERS_INV: Mapping[int, str]
    XPUB_HEADERS: Mapping[str, int]
    XPUB_HEADERS_INV: Mapping[int, str]

    @classmethod
    def max_checkpoint(cls) -> int:
        return max(0, len(cls.CHECKPOINTS) * 2016 - 1)

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(cls.GENESIS)[::-1]

    @classmethod
    def set_as_network(cls) -> None:
        global net
        net = cls

    _cached_default_servers = None
    @classproperty
    def DEFAULT_SERVERS(cls) -> Mapping[str, Mapping[str, str]]:
        if cls._cached_default_servers is None:
            default_file = {} if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            cls._cached_default_servers = read_json(os.path.join('chains', cls.NET_NAME, 'servers.json'), default_file)
        return cls._cached_default_servers

    _cached_fallback_lnnodes = None
    @classproperty
    def FALLBACK_LN_NODES(cls) -> Sequence[LNPeerAddr]:
        if cls._cached_fallback_lnnodes is None:
            default_file = {} if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            d = read_json(os.path.join('chains', cls.NET_NAME, 'fallback_lnnodes.json'), default_file)
            cls._cached_fallback_lnnodes = create_fallback_node_list(d)
        return cls._cached_fallback_lnnodes

    _cached_checkpoints = None
    @classproperty
    def CHECKPOINTS(cls) -> Sequence[Tuple[str, int]]:
        if cls._cached_checkpoints is None:
            default_file = [] if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            cls._cached_checkpoints = read_json(os.path.join('chains', cls.NET_NAME, 'checkpoints.json'), default_file)
        return cls._cached_checkpoints

    @classmethod
    def datadir_subdir(cls) -> Optional[str]:
        """The name of the folder in the filesystem.
        None means top-level, used by mainnet.
        """
        return cls.NET_NAME

    @classmethod
    def cli_flag(cls) -> str:
        """as used in e.g. `$ run_electrum --testnet4`"""
        return cls.NET_NAME

    @classmethod
    def config_key(cls) -> str:
        """as used for SimpleConfig.get()"""
        return cls.NET_NAME


class BitcoinMainnet(AbstractNet):

    NET_NAME = "mainnet"
    TESTNET = False
    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    SEGWIT_HRP = "bc"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
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
        'lseed.darosior.ninja',
    ]

    @classmethod
    def datadir_subdir(cls):
        return None


class BitcoinTestnet(AbstractNet):

    NET_NAME = "testnet"
    TESTNET = True
    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    SEGWIT_HRP = "tb"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}

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


class BitcoinTestnet4(BitcoinTestnet):

    NET_NAME = "testnet4"
    GENESIS = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
    LN_DNS_SEEDS = []


class BitcoinRegtest(BitcoinTestnet):

    NET_NAME = "regtest"
    SEGWIT_HRP = "bcrt"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    LN_DNS_SEEDS = []


class BitcoinSimnet(BitcoinTestnet):

    NET_NAME = "simnet"
    WIF_PREFIX = 0x64
    ADDRTYPE_P2PKH = 0x3f
    ADDRTYPE_P2SH = 0x7b
    SEGWIT_HRP = "sb"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "683e86bd5c6d110d91b94b97137ba6bfe02dbbdb8e3dff722a669b5d69d77af6"
    LN_DNS_SEEDS = []


class BitcoinSignet(BitcoinTestnet):

    NET_NAME = "signet"
    BOLT11_HRP = "tbs"
    GENESIS = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
    LN_DNS_SEEDS = []


NETS_LIST = tuple(all_subclasses(AbstractNet))  # type: Sequence[Type[AbstractNet]]

assert len(NETS_LIST) == len(set([chain.NET_NAME for chain in NETS_LIST])), "NET_NAME must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.datadir_subdir() for chain in NETS_LIST])), "datadir must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.cli_flag() for chain in NETS_LIST])), "cli_flag must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.config_key() for chain in NETS_LIST])), "config_key must be unique for each concrete AbstractNet"

# don't import net directly, import the module instead (so that net is singleton)
net = BitcoinMainnet  # type: Type[AbstractNet]
