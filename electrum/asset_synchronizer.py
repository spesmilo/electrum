# ElectrumSys - lightweight Bitcoin client
# Copyright (C) 2018 The ElectrumSys Developers
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

import asyncio
import threading
import asyncio
import itertools
import aiohttp
from aiohttp import client_exceptions
from collections import defaultdict
from typing import Dict, Optional, Set, Tuple, NamedTuple, Sequence, List
from . import bitcoin
from .util import block_explorer_tuple, profiler, bfh, TxMinedInfo, Satoshis, timestamp_to_datetime
from .i18n import _
from .logging import Logger
from .interface import RequestTimedOut
from .util import make_aiohttp_session
from collections import defaultdict
from functools import partial
class AssetHistoryItem(NamedTuple):
    txid: str
    transfer_type: str
    asset: str
    address: str
    symbol: str
    precision: int
    tx_mined_status: TxMinedInfo
    delta: Optional[int]
    fee: Optional[int]

class AssetItem(NamedTuple):
    asset: int
    symbol: str
    balance: int
    address: str
    precision: int

class AssetSynchronizer(Logger):
    """
    Sync asset + asset history and asset related transactions from Blockbook backend
    """

    def __init__(self, parent, config, xpub):
        self.wallet = parent  # type: Abstract_Wallet
        self.network = None  # type: Network
        Logger.__init__(self)
        self.config = config
        self.asset_list = [] # type: AssetItem
        self.asset_history = [] # type: AssetHistoryItem
        self.current_page = 1
        self.results_per_page = 25
        self.xpub = xpub
        self.total_pages = 1
        self.lastUrl = ""
        self.lastResponse = ""
        self.asset_list_dict = None

    def get_assets_from_json(self, jsonTokens):
        alist = []
        self.asset_list_dict = defaultdict(dict)
        if jsonTokens is None:
            return alist
        for token in jsonTokens:
            if token['type'] == 'SPTAllocated':
                asset_guid = int(token['contract'])
                asset_addr = token['name']
                assetItem = AssetItem(asset=asset_guid,
                    address=asset_addr,
                    symbol=token['symbol'],
                    balance=int(token['balance']),
                    precision=token['decimals'])
                alist.append(assetItem)
                self.asset_list_dict[asset_guid][asset_addr] = assetItem
        return alist
    

    async def fetch_assethistory(self):
        url = 'api/v2/xpub/' + self.xpub
        url += '?details=txslight&page=' + str(self.current_page) + '&pageSize=' + str(self.results_per_page) + '&filter=tokens'
        res = await self.send_request(url)
        if res is None:
            return
        if 'totalPages' not in res:
            return
        self.total_pages = res['totalPages']
        xpubTokens = {}
        missingTxs = []
        self.asset_history = []
        alist = []
        if 'tokens' in res:
            for token in res['tokens']:
                xpubTokens[token['name']] = True
            alist = self.get_assets_from_json(res['tokens'])
        if 'transactions' in res:
            transactions = res['transactions']
            for tx in transactions:
                if 'tokenTransfers' in tx:
                    delta = 0
                    fee = 0
                    for tokenTransfer in tx['tokenTransfers']:
                        asset_address = None
                        if tokenTransfer['fee']:
                            fee = int(tokenTransfer['fee'])
                        # find delta, if its sent from this xpub it should be negative based on tt total amount
                        # otherwise look in recipients to find the delta based on matching recipient to xpub token
                        if tokenTransfer['from'] in xpubTokens:
                            delta = -1*int(tokenTransfer['totalAmount'])
                            asset_address = tokenTransfer['from']
                        elif 'recipients' in tokenTransfer:
                            for recipient in tokenTransfer['recipients']:   
                                if recipient['to'] in xpubTokens:
                                    asset_address = recipient['to']
                                    delta = int(recipient['value'])
                                    break
                        self.asset_history.append(AssetHistoryItem(txid=tx['txid'],
                            transfer_type=tokenTransfer['type'],
                            asset=tokenTransfer['token'],
                            address=asset_address,
                            symbol=tokenTransfer['symbol'],
                            fee=fee,
                            precision=tokenTransfer['decimals'],
                            tx_mined_status=TxMinedInfo(height=tx['blockHeight'], conf=tx['confirmations'], timestamp=tx['blockTime']),
                            delta=delta))
        return alist

    def get_onchain_assethistory(self):
        for hist_item in self.asset_history:
            yield {
                'txid': hist_item.txid,
                'transfer_type': hist_item.transfer_type,
                'asset': hist_item.asset,
                'address': hist_item.address,
                'symbol': hist_item.symbol,
                'precision': hist_item.precision,
                'fee_sat': hist_item.fee,
                'height': hist_item.tx_mined_status.height,
                'confirmations': hist_item.tx_mined_status.conf,
                'timestamp': hist_item.tx_mined_status.timestamp,
                'incoming': True if hist_item.delta>0 else False,
                'bc_value': Satoshis(hist_item.delta),
                'date': timestamp_to_datetime(hist_item.tx_mined_status.timestamp),
                'label': self.wallet.get_label(hist_item.txid),
            }

    async def start_network(self, network):
        self.network = network
        self.asset_list = await self.fetch_assethistory()

    async def increase_page(self, callback):
        if self.current_page < self.total_pages:
            self.current_page = self.current_page + 1
            self.asset_list = await self.fetch_assethistory()
            if len(self.asset_list) == 0:
                self.current_page = self.current_page - 1
                self.asset_list = await self.fetch_assethistory()
            callback()

    async def decrease_page(self, callback):
        if self.current_page > 1:
            self.current_page = self.current_page - 1
            self.asset_list = await self.fetch_assethistory()
            callback()

    async def change_results_per_page(self, results_page, callback):
        self.results_per_page = results_page
        self.asset_list = await self.fetch_assethistory()
        callback()

    def get_assets(self):
        return self.asset_list

    def get_asset(self, asset_guid, asset_address=None, all_allocations = False):
        if asset_guid is None:
            return None
        if self.asset_list_dict is None or int(asset_guid) not in self.asset_list_dict:
            return None
        assets = self.asset_list_dict.get(int(asset_guid), {})
        if all_allocations is True:
            return iter(assets.values())
        elif asset_address is None:
            return next(iter(assets.values()))
        elif asset_address is not None and asset_address in assets:
            return assets.get(asset_address)
        return None

    async def synchronize_assets(self, callback=None):

        result_ = await self.fetch_assethistory()
        new_asset_list = []
        changed_asset = None
        if result_ is not None:
            for asset in result_:
                new_asset_list.append(asset)
            if self.asset_list is not None:
                for x in range(len(new_asset_list)):
                    if x < len(new_asset_list) and x < len(self.asset_list):
                        if self.asset_list[x].asset != new_asset_list[x].asset or self.asset_list[x].address != new_asset_list[x].address or self.asset_list[x].balance != new_asset_list[x].balance:
                            changed_asset = new_asset_list[x]
                            break
        self.asset_list = new_asset_list
        if callback is not None and self.current_page == 1:
            callback(changed_asset)


    async def send_request(self, cmd):
        if self.network is None:
            return None
        # APIs must have https
        be_tuple = block_explorer_tuple(self.config)
        if not be_tuple:
            return None
        explorer_url, explorer_dict = be_tuple
        url = ''.join([explorer_url, cmd])
        proxy = self.network.proxy if self.network else None
        try:
            async with make_aiohttp_session(proxy) as session:
                async with session.get(url) as response:
                    response.raise_for_status()
                    return await response.json(content_type=None)
        except RequestTimedOut as e:
            self.logger.info(f'timeout on api backend {url}')
        except aiohttp.client_exceptions.ClientConnectorError:
            self.logger.info(f'could not contact explorer api backend {url}')
        except Exception as e:
            self.logger.info("caught unknown exceptionrror {}".format(e))
        return None



    async def create_assetallocation_send(self, from_address, to_address, asset_guid, amount):
        url = 'api/v2/assetallocationsend/' + str(asset_guid) + '?to=' + to_address + '&from='+from_address + '&amount=' + str(amount)
        # seems to call twice in upstream code per request
        if self.lastUrl == url:
            return self.lastResponse
        res = await self.send_request(url)
        self.lastResponse = None
        if res is not None:
            self.lastResponse = res['tx']['hex']
            self.lastUrl = url
        return self.lastResponse

 