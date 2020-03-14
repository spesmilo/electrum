# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum Developers
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
from collections import defaultdict
from typing import Dict, Optional, Set, Tuple, NamedTuple, Sequence, List
from . import bitcoin
from .util import block_explorer_tuple, profiler, bfh, TxMinedInfo, Satoshis, timestamp_to_datetime
from .i18n import _
from .logging import Logger
from .interface import RequestTimedOut
from .util import make_aiohttp_session

class AssetHistoryItem(NamedTuple):
    txid: str
    transfer_type: str
    asset: int
    symbol: str
    precision: int
    tx_mined_status: TxMinedInfo
    delta: Optional[int]
    fee: Optional[int]
    balance: Optional[int]

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
        self.asset_list_dict = {} # type: AssetItem
        self.current_page = 0
        self.results_per_page = 25
        self.xpub = xpub
        self.total_pages = 0

    def get_assets_from_json(self, jsonTokens):
        alist = []
        if jsonTokens is None:
            return
        for token in jsonTokens:
            if token['type'] == 'SPTAllocated':
                alist.append(AssetItem(asset=int(token['contract']),
                    address=token['name'],
                    symbol=token['symbol'],
                    balance=int(token['balance']),
                    precision=token['decimals']))
        self.create_asset_list_dict(alist)
        return alist
    
    def create_asset_list_dict(self, assets):
        for a in assets:
            self.asset_list_dict[a.asset] = a

    async def fetch_assets(self):
        url = 'api/v2/xpub/' + self.xpub
        res = await self.send_request(url)
        alist = []
        if res is not None and 'tokens' in res:
            self.total_pages = res['totalPages']
            alist = self.get_assets_from_json(res['tokens'])
        return alist

    async def fetch_assethistory(self):
        url = 'api/v2/xpub/' + self.xpub
        url += '?details=txs&page=' + str(self.current_page) + '&pageSize=' + str(self.results_per_page)
        res = await self.send_request(url)
        if res is None:
            return
        self.total_pages = res['totalPages']
        xpubTokens = {}
        if 'tokens' in res:
            for token in res['tokens']:
                xpubTokens[token['name']] = True
            self.asset_list = self.get_assets_from_json(res['tokens'])
        if 'transactions' in res:
            transactions = res['transactions']
            for tx in transactions:
                if 'tokenTransfers' in tx:
                    delta = 0
                    fee = 0
                    for tokenTransfer in tx['tokenTransfers']:
                        if tokenTransfer['fee']:
                            fee = int(tokenTransfer['fee'])
                        # find delta, if its sent from this xpub it should be negative based on tt total amount
                        # otherwise look in recipients to find the delta based on matching recipient to xpub token
                        if tokenTransfer['from'] in xpubTokens:
                            delta = -1*int(tokenTransfer['totalAmount'])
                        elif 'recipients' in tokenTransfer:
                            for recipient in tokenTransfer['recipients']:   
                                if recipient['to'] in xpubTokens:
                                    delta = int(recipient['value'])
                                    break
                        self.asset_history.append(AssetHistoryItem(txid=tx['txid'],
                            transfer_type=tokenTransfer['type'],
                            asset=tokenTransfer['token'],
                            symbol=tokenTransfer['symbol'],
                            fee=fee,
                            precision=tokenTransfer['decimals'],
                            balance=self.get_asset_balance(tokenTransfer['token']),
                            tx_mined_status=TxMinedInfo(height=tx['blockHeight'], conf=tx['confirmations'], timestamp=tx['blockTime']),
                            delta=delta))


    def get_onchain_assethistory(self):
        for hist_item in self.asset_history:
            yield {
                'txid': hist_item.txid,
                'transfer_type': hist_item.transfer_type,
                'asset': hist_item.asset,
                'symbol': hist_item.symbol,
                'precision': hist_item.precision,
                'fee_sat': hist_item.fee,
                'height': hist_item.tx_mined_status.height,
                'confirmations': hist_item.tx_mined_status.conf,
                'timestamp': hist_item.tx_mined_status.timestamp,
                'incoming': True if hist_item.delta>0 else False,
                'bc_value': Satoshis(hist_item.delta),
                'bc_balance': Satoshis(hist_item.balance),
                'date': timestamp_to_datetime(hist_item.tx_mined_status.timestamp),
                'label': self.wallet.get_label(hist_item.txid),
            }

    async def start_network(self, network):
        self.network = network
        await self.fetch_assethistory()
    
    async def change_page(self, page):
        if page >= self.total_pages and page <= self.total_pages:
            self.current_page = page
            await self.fetch_assethistory()

    async def increase_page(self, page):
        self.current_page = self.current_page + 1
        await self.fetch_assethistory()
        if page > self.total_pages or len(self.asset_list) is 0:
            self.current_page = self.current_page - 1

    async def decrease_page(self, page):
        self.current_page = self.current_page - 1
        if self.current_page < 0:
            self.current_page = 0
        await self.fetch_assethistory()

    async def change_results_per_page(self, results_page):
        self.results_per_page = results_page
        await self.fetch_assethistory()

    def get_assets(self):
        return self.asset_list

    def get_asset(self, asset_guid):
        if asset_guid is None:
            return None
        if asset_guid in self.asset_list_dict:
            return self.asset_list_dict[asset_guid]
        else:
            return None

    def get_asset_symbol(self, asset_guid):
        if asset_guid is None:
            return "SYS"
        if asset_guid in self.asset_list_dict:
            return self.asset_list_dict[asset_guid].symbol
        else:
            return "UNKNOWN"

    def get_asset_balance(self, asset_guid):
        if asset_guid is None:
            return 0
        if asset_guid in self.asset_list_dict:
            return self.asset_list_dict[asset_guid].balance
        else:
            return 0            

    async def synchronize_assets(self, callback=None, notify_flag=True):
        try:
            self.logger.info("synchronizing assets")
            try:
                result_ = await self.fetch_assets()
            except RuntimeError as e:
                self.logger.info("synchronize_assets: asyncio error {}".format(e))
                return
            new_asset_list = []
            changed_asset = None
            for asset in result_:
                new_asset_list.append(asset)
            
            for x in range(len(self.asset_list)):
                if self.asset_list[x].asset != new_asset_list[x].asset or self.asset_list[x].address != new_asset_list[x].address or self.asset_list[x].balance != new_asset_list[x].balance:
                    changed_asset = new_asset_list[x]
                    break
            self.asset_list = new_asset_list
            if callback is not None:
                callback(changed_asset, notify_flag)
        except RequestTimedOut as e:
            if e is not TimeoutError:
                raise e

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
        async with make_aiohttp_session(proxy) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json(content_type=None)

    async def create_assetallocation_send(self, from_address, to_address, asset_guid, amount):
        res = await self.send_request('api/v2/assetallocationsend/' + asset_guid + '?to=' + to_address + '&from='+from_address + '&amount=' + amount)
        return res['hex']

 