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
    FIXEDFEE = 100000
    CONTRACTINTX = True
    BASIC_HEADER_SIZE = 172
    MIN_HEADER_SIZE = 176
    WIF_PREFIX = 0xB4
    ADDRTYPE_P2PKH = 38
    ADDRTYPE_P2SH = 97
    SEGWIT_HRP = "bc"
    GENESIS = "e6d7cd550c53bb3e973e55e996712a2e1b1c74975301ec6a56b03df931b561c3"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    MAPPING_URL = 'https://s3.eu-west-2.amazonaws.com/gtsa-mapping/map.json'
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

    CONTROLER1 = "04ac939ba82f6915c5b2e9232548dd59a97bfdd1891dcd6fb0405acd40c4e35ac1398940aac7b5220587a33f260c9cd0906883e54e2880812d7e39188d2d0cd4da"
    CONTROLER2 = "041a7d07efe2164258086597e62edd115aba03676cf4d91f3f21ba09b64a926fb2ea939b23b851024f49afa3377ac4e8e964d07a011b7bf66caef2f765dc6902a4"
    CONTROLER3 = "0405ed5282cbb8614b0b5ae43e448796846ed24b9406c23a12f6b108a8e37c49ef9828f92e5cc2237a789030198ed5a7f5d56af7ce27cdd4fa0da6b7e06d154fe8"
    #Address the whitelist tokens are initially paid to (defined in the genesis block)
    WHITELISTCOINSDESTINATION = "76a914cb7d39ef3d41ceef1ac6f0bfe3ae2003365158d288ac"
    WHITELISTCOINSADDRESS = "GcPsbwmP3VFFxGWPUw9VkzjZw4q9BkKa8C"
    WHITELISTASSET="d109a2432528b0a9208e7f4258f569e246c25bd0cd90f4d8160f1704be833c23"

    CHALLENGE = "5321024cc60ff6ca8423c8353142fab8b4aa8b42e66eac2ae51a7cde1eaeb54a73a31e21034878127e5f0a5c84e775d754f02bcea9393c17b7fc05a01a2c011f7a419e6f932103b7d99275aba3db614faeeba3920295e8d661a3a0a705d999b8a38aca0f8fc5d321039d1175c43f855f003fd1e980b618b3d504f2099754b8afa3667ead04b9dbb6d921027c2e025fb4d41e7c4b757a722bff6172233fa576b0aac7d5d8e4e32cfbf2a1df55ae"
    ENCRYPTED_WHITELIST=False

    
# Current Testnet purposes
class OceanTestnet(OceanMainnet):
    TESTNET = True
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = []
    WIF_PREFIX = 0xEF
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
    ENCRYPTED_WHITELIST=False
    
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
    ENCRYPTED_WHITELIST=False
    
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
