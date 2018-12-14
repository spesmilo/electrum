# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2017 Neil Booth
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

import json
import os

def read_json_dict(filename):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = {}
    return r

class NetworkConstants:

    # Version numbers for BIP32 extended keys
    # standard: xprv, xpub
    XPRV_HEADERS = {
        'standard': 0x0488ade4,
    }

    XPUB_HEADERS = {
        'standard': 0x0488b21e,
    }

    @classmethod
    def set_mainnet(cls):
        cls.TESTNET = False
        cls.WIF_PREFIX = 0x80
        cls.ADDRTYPE_P2PKH = 0
        cls.ADDRTYPE_P2PKH_BITPAY = 28
        cls.ADDRTYPE_P2SH = 5
        cls.ADDRTYPE_P2SH_BITPAY = 40
        cls.CASHADDR_PREFIX = "bitcoincash"
        cls.HEADERS_URL = "http://bitcoincash.com/files/blockchain_headers"
        cls.GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        cls.DEFAULT_PORTS = {'t': '50001', 's': '50002'}
        cls.DEFAULT_SERVERS = read_json_dict('servers.json')
        cls.TITLE = 'Electron Cash'

        # Bitcoin Cash fork block specification
        cls.BITCOIN_CASH_FORK_BLOCK_HEIGHT = 478559
        cls.BITCOIN_CASH_FORK_BLOCK_HASH = "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"

        # Note to Jonald or anyone reading this: the below is misleadingly named.  It's not a simple
        # MERKLE_ROOT but a MERKLE_PROOF which is basically the hashes of all MERKLE_ROOTS up until and including
        # this block. Consult the ElectrumX documentation.
        # To get this value you need to connect to an ElectrumX server you trust and issue it a protocol command.
        # blockchain.block.header (see ElectrumX docs)
        cls.VERIFICATION_BLOCK_MERKLE_ROOT = "b8f9b1649d0bba75e2c2ea4be73395a0967397003f33a40653caca0ec6a73baa"
        cls.VERIFICATION_BLOCK_HEIGHT = 560644
        
    @classmethod
    def set_testnet(cls):
        cls.TESTNET = True
        cls.WIF_PREFIX = 0xef
        cls.ADDRTYPE_P2PKH = 111
        cls.ADDRTYPE_P2PKH_BITPAY = 111  # Unsure
        cls.ADDRTYPE_P2SH = 196
        cls.ADDRTYPE_P2SH_BITPAY = 196  # Unsure
        cls.CASHADDR_PREFIX = "bchtest"
        cls.HEADERS_URL = "http://bitcoincash.com/files/testnet_headers"
        cls.GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        cls.DEFAULT_PORTS = {'t':'51001', 's':'51002'}
        cls.DEFAULT_SERVERS = read_json_dict('servers_testnet.json')
        cls.TITLE = 'Electron Cash Testnet'

        # Bitcoin Cash fork block specification
        cls.BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
        cls.BITCOIN_CASH_FORK_BLOCK_HASH = "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5"
        
        cls.VERIFICATION_BLOCK_MERKLE_ROOT = "c3cc7a7b6fe5e0ff19b750ae200ae93664b3abf09bf510e26e15ba338afe1f1a"
        cls.VERIFICATION_BLOCK_HEIGHT = 1273800


NetworkConstants.set_mainnet()
