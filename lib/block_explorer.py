# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
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

from .address import Address
from .networks import NetworkConstants

mainnet_block_explorers = {
    'Blockchair.com': ('https://blockchair.com/bitcoin-cash',
                       Address.FMT_LEGACY,
                        {'tx': 'transaction', 'addr': 'address'}),
}

testnet_block_explorers = {
    'Blocktrail.com': ('https://www.blocktrail.com/tBCC',
                       Address.FMT_LEGACY,
                       {'tx': 'tx', 'addr': 'address'}),
    'system default': ('blockchain:',
                       Address.FMT_LEGACY,
                       {'tx': 'tx', 'addr': 'address'}),
}

def _info():
    if NetworkConstants.TESTNET:
        return testnet_block_explorers
    return mainnet_block_explorers

def _tuple(config):
    return _info().get(from_config(config))

def from_config(config):
    return config.get('block_explorer', 'Blockchair.com')

def URL(config, kind, item):
    be_tuple = _tuple(config)
    if not be_tuple:
        return
    url_base, addr_fmt, parts = be_tuple
    kind_str = parts.get(kind)
    if not kind_str:
        return
    if kind == 'addr':
        assert isinstance(item, Address)
        item = item.to_string(addr_fmt)
    return "/".join([url_base, kind_str, item])

def sorted_list():
    return sorted(_info())
