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
    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    SEGWIT_HRP = "bc"
    GENESIS = "5ab1cb43487f39b1e279683418ca6c144da720ed7340e4df85b5f6fc6148a187"
#    GENESIS = "c8a0dc6295a81c86d103ea677a1e6e7e5b9a11a7ee702a8543f9b6a51694d51c"
#    GENESIS = "9c279ca34ead7ca687cd84cae9c02f274ac1faacdb4ff2fa3179f21d73872d22"
    GENESIS = "10f8615e5cd17909a859b5b0aafc3fcf1db31b5cd31243e57d4dd9afa5754539"
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

    CONTROLER1 = "0435c3948e09eca97ed55f22383991e6bc3aa8a8eb54c4d28f069380ec5f0d33d6321137f3ed13ebdfea8cb057fac5532b8773a344632ab83c0effd935f36b60c4"
    CONTROLER2 = "04441ef52d1923962e44fd86c0bc019dd768988f603d625791a721f855ddcf6320b2fad5507dc16acf4beace8658b5092b450f7c4d32b15b7351c0ef2afe7574e4"
    CONTROLER3 = "0424405f3350d375edb7b0fb5846a4c794ff0cb76d01e94098a56dd5a6008a8dc13980e5ca463d3ea864f17690d049a197dce0e766dae1806412e45105d3761d73"
    #Address the whitelist tokens are initially paid to (defined in the genesis block)
    WHITELISTCOINSDESTINATION = "76a914f9203678f55c1fd3d99831836ff01fbe1071ccd788ac"
    #"76a9144ff9b5c6885f87fb5519cc45c1474f301a73224a88ac"
    #Derive using e.g. ocean-cli decodescript
    WHITELISTCOINSADDRESS = "2dx91EU6mn4yqAJhrqhi4fbywMeW3LbLRzD"
    #"18HsXKCZxZ4Cc6W1oHK4noAvf1k5HaEme2"
    WHITELISTASSET="06ac64b25aa03694714f4c6ab47e6216600d39878b660714d7e553ed4d465307"

# Current Testnet purposes
class OceanTestnet(OceanMainnet):
    TESTNET = True
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = []
    ADDRTYPE_P2PKH = 235
    ADDRTYPE_P2SH = 75               
    GENESIS = "5ab1cb43487f39b1e279683418ca6c144da720ed7340e4df85b5f6fc6148a187"

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

    CONTROLER1 = "0435c3948e09eca97ed55f22383991e6bc3aa8a8eb54c4d28f069380ec5f0d33d6321137f3ed13ebdfea8cb057fac5532b8773a344632ab83c0effd935f36b60c4"
    CONTROLER2 = "04441ef52d1923962e44fd86c0bc019dd768988f603d625791a721f855ddcf6320b2fad5507dc16acf4beace8658b5092b450f7c4d32b15b7351c0ef2afe7574e4"
    CONTROLER3 = "0424405f3350d375edb7b0fb5846a4c794ff0cb76d01e94098a56dd5a6008a8dc13980e5ca463d3ea864f17690d049a197dce0e766dae1806412e45105d3761d73"
 
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
