# This file is part of the TREZOR project.
#
# Copyright (C) 2012-2016 Marek Palatinus <slush@satoshilabs.com>
# Copyright (C) 2012-2016 Pavol Rusnak <stick@satoshilabs.com>
# Copyright (C) 2016      Jochen Hoenicke <hoenicke@gmail.com>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

import binascii
from decimal import Decimal
import requests
import json
import struct

from . import types_pb2 as proto_types

cache_dir = None


def pack_varint(n):
    if n < 253:
        return struct.pack("<B", n)
    elif n <= 0xFFFF:
        return struct.pack("<BH", 253, n)
    elif n <= 0xFFFFFFFF:
        return struct.pack("<BL", 254, n)
    else:
        return struct.pack("<BQ", 255, n)


class TxApi(object):

    def __init__(self, network, url):
        self.network = network
        self.url = url

    def fetch_json(self, url, resource, resourceid):
        global cache_dir
        if cache_dir:
            cache_file = '%s/%s_%s_%s.json' % (cache_dir, self.network, resource, resourceid)
            try: # looking into cache first
                j = json.load(open(cache_file))
                return j
            except:
                pass
        try:
            r = requests.get('%s/%s/%s' % (self.url, resource, resourceid), headers={'User-agent': 'Mozilla/5.0'})
            j = r.json()
        except:
            raise Exception('URL error: %s' % url)
        if cache_file:
            try: # saving into cache
                json.dump(j, open(cache_file, 'w'))
            except:
                pass
        return j

    def get_tx(self, txhash):
        raise NotImplementedError


class TxApiInsight(TxApi):

    def __init__(self, network, url, zcash=None):
        super(TxApiInsight, self).__init__(network, url)
        self.zcash = zcash

    def get_tx(self, txhash):

        data = self.fetch_json(self.url, 'tx', txhash)

        t = proto_types.TransactionType()
        t.version = data['version']
        t.lock_time = data['locktime']

        for vin in data['vin']:
            i = t.inputs.add()
            if 'coinbase' in vin.keys():
                i.prev_hash = b"\0"*32
                i.prev_index = 0xffffffff # signed int -1
                i.script_sig = binascii.unhexlify(vin['coinbase'])
                i.sequence = vin['sequence']

            else:
                i.prev_hash = binascii.unhexlify(vin['txid'])
                i.prev_index = vin['vout']
                i.script_sig = binascii.unhexlify(vin['scriptSig']['hex'])
                i.sequence = vin['sequence']

        for vout in data['vout']:
            o = t.bin_outputs.add()
            o.amount = int(Decimal(str(vout['value'])) * 100000000)
            o.script_pubkey = binascii.unhexlify(vout['scriptPubKey']['hex'])

        if self.zcash:
            if t.version == 2:
                joinsplit_cnt = len(data['vjoinsplit'])
                if joinsplit_cnt == 0:
                    t.extra_data =b'\x00'
                else:
                    if joinsplit_cnt >= 253:
                        # we assume cnt < 253, so we can treat varIntLen(cnt) as 1
                        raise ValueError('Too many joinsplits')
                    extra_data_len = 1 + joinsplit_cnt * 1802 + 32 + 64
                    raw = self.fetch_json(self.url, 'rawtx', txhash)
                    raw = binascii.unhexlify(raw['rawtx'])
                    t.extra_data = raw[-extra_data_len:]

        if "_dash" in self.network:
            dip2_type = data.get("type", 0)

            if t.version == 3 and dip2_type != 0:
                # It's a DIP2 special TX with payload

                if "extraPayloadSize" not in data or "extraPayload" not in data:
                    raise ValueError("Payload data missing in DIP2 transaction")

                if data["extraPayloadSize"] * 2 != len(data["extraPayload"]):
                    raise ValueError("length mismatch")
                t.extra_data = pack_varint(data["extraPayloadSize"]) + binascii.unhexlify(
                    data["extraPayload"]
                )

            # Trezor (and therefore KeepKey) firmware doesn't understand the
            # split of version and type, so let's mimic the old serialization
            # format
            t.version |= dip2_type << 16

        return t

    def get_raw_tx(self, txhash):
        data = self.fetch_json(self.url, 'rawtx', txhash)['rawtx']
        return data


TxApiBitcoin = TxApiInsight(network='insight_bitcoin', url='https://btc.coinquery.com/api')
TxApiTestnet = TxApiInsight(network='insight_testnet', url='https://test-insight.bitpay.com/api')
TxApiZcashTestnet = TxApiInsight(network='insight_zcashtestnet', url='https://explorer.testnet.z.cash/api', zcash=True)
TxApiBitcoinGold = TxApiInsight(network='insight_bitcoingold', url='https://btg.coinquery.com/api')
TxApiGroestlcoin = TxApiInsight(network='insight_groestlcoin', url='https://groestlsight.groestlcoin.org/api')
TxApiGroestlcoinTestnet = TxApiInsight(network='insight_groestlcoin_testnet', url='https://groestlsight-test.groestlcoin.org/api')
TxApiDash = TxApiInsight(network='insight_dash', url='https://dash.coinquery.com/api')
