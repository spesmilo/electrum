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
from electrum import bitcoin
from .bitcoin import *


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r

class OceanMainnet:

    TESTNET = False
    BASIC_HEADER_SIZE = 172
    MIN_HEADER_SIZE = 176
    WIF_PREFIX = 0xB4
    ADDRTYPE_P2PKH = 38
    ADDRTYPE_P2SH = 97
    SEGWIT_HRP = "bc"
    GENESIS = "ce93da5318b228bec9e48cb0867fdc1cd02ca0458463b255ac447ddacb7ae935"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    MAPPING_URL = 'https://s3.eu-west-2.amazonaws.com/cb-mapping/map.json'
    CHECKPOINTS = []    # no handling for checkpoins

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh':  0x0295b005,  # Yprv
        'p2wpkh':      0x04b2430c,  # zprv
        'p2wsh':       0x02aa7a99,  # Zprv

    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh':  0x0295b43f,  # Ypub
        'p2wpkh':      0x04b24746,  # zpub
        'p2wsh':       0x02aa7ed3,  # Zpub

    }
    BIP44_COIN_TYPE = 0

    CONTROLER1 = "02a706d2bf4c2fbb80a67781581271d6e6ce776d48e604b23263a6057f6a9b4eef"
    CONTROLER2 = "032aca867e13ab11ca30094bd1e0739c9ce67fbefcc5ccd5d2cb0556c3fc9a886f"
    CONTROLER3 = "032aca867e13ab11ca30094bd1e0739c9ce67fbefcc5ccd5d2cb0556c3fc9a886f"
    #Address the whitelist tokens are initially paid to (defined in the genesis block)
    WHITELISTCOINSDESTINATION = "76a91424ed6c146ab262dd8493d618e827bde0a642f24088ac"
    WHITELISTCOINSADDRESS = "GMDBAR4rYVEz3k79SPcdYMLQDKuSJcuauz"
    WHITELISTASSET="6a75f2c357247f703fcf2144c849b09290cf84d9a53afedbaa01f79fd1747eb5"

    CHALLENGE = "532103041f9d9edc4e494b07eec7d3f36cedd4b2cfbb6fe038b6efaa5f56b9636abd7b21037c06b0c66c98468d64bb43aff91a65c0a576113d8d978c3af191e38845ae5dab21031bd16518d76451e7cf13f64087e4ae4816d08ae1d579fa6c172dcfe4476bd7da210226c839b56b99af781bbb4ce14365744253ae75ffe6f9182dd7b0df95c439537a21023cd2fc00c9cb185b4c0da16a45a1039e16709a61fb22340645790b7d1391b66055ae"

# Current Testnet purposes
class OceanTestnet(OceanMainnet):
    TESTNET = True
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = []
    ADDRTYPE_P2PKH = 235
    ADDRTYPE_P2SH = 75
    WHITELISTCOINSDESTINATION = "76a914f9203678f55c1fd3d99831836ff01fbe1071ccd788ac"
    WHITELISTCOINSADDRESS = "2dx91EU6mn4yqAJhrqhi4fbywMeW3LbLRzD"
    GENESIS = "8fe2b5ce49136a9dd9052717a4dd43ebd884d599de66dde590cd13a448f5f55e"

    XPRV_HEADERS = {
        'standard':    0x04358394,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh':  0x0295b005,  # Yprv
        'p2wpkh':      0x04b2430c,  # zprv
        'p2wsh':       0x02aa7a99,  # Zprv

    }

    XPUB_HEADERS = {
        'standard':    0x043587cf,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh':  0x0295b43f,  # Ypub
        'p2wpkh':      0x04b24746,  # zpub
        'p2wsh':       0x02aa7ed3,  # Zpub
    }

    CONTROLER1 = "048249c166d63d2b76c958bab0ad13bf7009121acfe1c2727701df8a4fc3f3d045744cf6894db9df71ce9ef64d2bb5c6d80a1318b74dfee4ad69137469defa9d2a"
    CONTROLER2 = "04441ef52d1923962e44fd86c0bc019dd768988f603d625791a721f855ddcf6320b2fad5507dc16acf4beace8658b5092b450f7c4d32b15b7351c0ef2afe7574e4"
    CONTROLER3 = "04ac8725ca6d2f68ec65ec01ae335c94d28168df07d64f66a70b7def687f2c352827ffaa540c61a4f68b0cf63c9a99fb61dccebfe7b9b0a6e75bbd4d6e5d3aba59"

    MAPPING_URL = 'https://s3.eu-west-2.amazonaws.com/cb-mapping/map.json'

class OceanRegtest(OceanMainnet):

    TESTNET = True
    WIF_PREFIX = 0xef

    # From Ocean but never used
    #ADDRTYPE_P2PKH = 235
    #ADDRTYPE_P2SH = 75

    # Prefixes that were used for test_wallet_vertical.py case generation
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196

    SEGWIT_HRP = "tb"
    GENESIS = ""
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh':  0x024285b5,  # Uprv
        'p2wpkh':      0x045f18bc,  # vprv
        'p2wsh':       0x02575048,  # Vprv
    }
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh':  0x024289ef,  # Upub
        'p2wpkh':      0x045f1cf6,  # vpub
        'p2wsh':       0x02575483,  # Vpub
    }

    BIP44_COIN_TYPE = 1

# don't import net directly, import the module instead (so that net is singleton)
net = OceanMainnet

def set_simnet():
    return

def set_mainnet():
    global net
    net = OceanMainnet

def set_testnet():
    global net
    net = OceanTestnet

def set_regtest():
    global net
    net = OceanRegtest
