#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
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
import hashlib
import json
from typing import Union, TYPE_CHECKING

import base64

from electrum import util
from electrum.plugin import BasePlugin, hook
from electrum.crypto import aes_encrypt_with_iv, aes_decrypt_with_iv
from electrum.i18n import _
from electrum.util import log_exceptions, ignore_exceptions, make_aiohttp_session
from electrum.network import Network

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


class ErrorConnectingServer(Exception):
    def __init__(self, reason: Union[str, Exception] = None):
        self.reason = reason

    def __str__(self):
        header = _("Error connecting to {} server").format('Labels')
        reason = self.reason
        if isinstance(reason, BaseException):
            reason = repr(reason)
        return f"{header}: {reason}" if reason else header


class LabelsPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.target_host = 'labels.electrum.org'
        self.wallets = {}

    def encode(self, wallet: 'Abstract_Wallet', msg: str) -> str:
        password, iv, wallet_id = self.wallets[wallet]
        encrypted = aes_encrypt_with_iv(password, iv, msg.encode('utf8'))
        # FIXME: ^ we are reusing the IV between all labels in the wallet, in CBC mode...
        return base64.b64encode(encrypted).decode()

    def decode(self, wallet: 'Abstract_Wallet', message: str) -> str:
        password, iv, wallet_id = self.wallets[wallet]
        decoded = base64.b64decode(message, validate=True)
        decrypted = aes_decrypt_with_iv(password, iv, decoded)
        return decrypted.decode('utf8')

    def get_nonce(self, wallet: 'Abstract_Wallet'):
        # nonce is the nonce to be used with the next change
        nonce = wallet.db.get('wallet_nonce')
        if nonce is None:
            nonce = 1
            self.set_nonce(wallet, nonce)
        return nonce

    def set_nonce(self, wallet: 'Abstract_Wallet', nonce):
        self.logger.info(f"set {wallet.basename()} nonce to {nonce}")
        wallet.db.put("wallet_nonce", nonce)

    @hook
    def set_label(self, wallet: 'Abstract_Wallet', item, label):
        if wallet not in self.wallets:
            return
        if not item:
            return
        if label is None:
            # note: the server should not know whether a label is empty
            #       FIXME but it does! we are reusing the IV with AES-CBC: there is no randomness between labels,
            #       all empty labels in given wallet look the same.
            label = ''
        nonce = self.get_nonce(wallet)
        wallet_id = self.wallets[wallet][2]
        bundle = {
            "walletId": wallet_id,
            "walletNonce": nonce,
            "externalId": self.encode(wallet, item),
            "encryptedLabel": self.encode(wallet, label)
        }
        asyncio.run_coroutine_threadsafe(self.do_post_safe("/label", bundle), wallet.network.asyncio_loop)
        # Caller will write the wallet
        self.set_nonce(wallet, nonce + 1)

    @ignore_exceptions
    @log_exceptions
    async def do_post_safe(self, *args):
        await self.do_post(*args)

    async def do_get(self, url = "/labels"):
        url = 'https://' + self.target_host + url
        network = Network.get_instance()
        proxy = network.proxy if network else None
        async with make_aiohttp_session(proxy) as session:
            async with session.get(url) as result:
                return await result.json()

    async def do_post(self, url = "/labels", data=None):
        url = 'https://' + self.target_host + url
        network = Network.get_instance()
        proxy = network.proxy if network else None
        async with make_aiohttp_session(proxy) as session:
            async with session.post(url, json=data) as result:
                try:
                    return await result.json()
                except Exception as e:
                    raise Exception('Could not decode: ' + await result.text()) from e

    async def push_thread(self, wallet: 'Abstract_Wallet') -> int:
        wallet_data = self.wallets.get(wallet, None)
        if not wallet_data:
            raise Exception('Wallet {} not loaded'.format(wallet))
        wallet_id = wallet_data[2]
        bundle = {"labels": [],
                  "walletId": wallet_id,
                  "walletNonce": self.get_nonce(wallet)}
        for key, value in wallet.get_all_labels().items():
            try:
                encoded_key = self.encode(wallet, key)
                encoded_value = self.encode(wallet, value)
            except Exception:
                self.logger.info(f'cannot encode {repr(key)} {repr(value)}')
                continue
            bundle["labels"].append({'encryptedLabel': encoded_value,
                                     'externalId': encoded_key})
        await self.do_post("/labels", bundle)
        return len(bundle['labels'])

    async def pull_thread(self, wallet: 'Abstract_Wallet', force: bool) -> int:
        wallet_data = self.wallets.get(wallet, None)
        if not wallet_data:
            raise Exception('Wallet {} not loaded'.format(wallet))
        wallet_id = wallet_data[2]
        nonce = 1 if force else self.get_nonce(wallet) - 1
        self.logger.info(f"asking for labels since nonce {nonce}")
        try:
            response = await self.do_get("/labels/since/%d/for/%s" % (nonce, wallet_id))
        except Exception as e:
            raise ErrorConnectingServer(e) from e
        if response["labels"] is None or len(response["labels"]) == 0:
            self.logger.info('no new labels')
            return 0

        self.logger.info(f'received {len(response["labels"])} labels')
        result = {}
        for label in response["labels"]:
            try:
                key = self.decode(wallet, label["externalId"])
                value = self.decode(wallet, label["encryptedLabel"])
            except Exception:
                continue
            try:
                json.dumps(key)
                json.dumps(value)
            except Exception:
                self.logger.info(f'error: no json {key}')
                continue
            if value:
                result[key] = value

        for key, value in result.items():
            wallet._set_label(key, value)

        self.set_nonce(wallet, response["nonce"] + 1)
        util.trigger_callback('labels_received', wallet, result)
        self.on_pulled(wallet)
        return len(result)

    def on_pulled(self, wallet: 'Abstract_Wallet') -> None:
        pass

    @ignore_exceptions
    @log_exceptions
    async def pull_safe_thread(self, wallet: 'Abstract_Wallet', force: bool):
        try:
            await self.pull_thread(wallet, force)
        except ErrorConnectingServer as e:
            self.logger.info(repr(e))

    def pull(self, wallet: 'Abstract_Wallet', force: bool):
        if not wallet.network:
            raise Exception(_('You are offline.'))
        return asyncio.run_coroutine_threadsafe(self.pull_thread(wallet, force), wallet.network.asyncio_loop).result()

    def push(self, wallet: 'Abstract_Wallet'):
        if not wallet.network:
            raise Exception(_('You are offline.'))
        return asyncio.run_coroutine_threadsafe(self.push_thread(wallet), wallet.network.asyncio_loop).result()

    def start_wallet(self, wallet: 'Abstract_Wallet'):
        if not wallet.network:
            return  # 'offline' mode
        mpk = wallet.get_fingerprint()
        if not mpk:
            return
        mpk = mpk.encode('ascii')
        password = hashlib.sha1(mpk).hexdigest()[:32].encode('ascii')
        iv = hashlib.sha256(password).digest()[:16]
        wallet_id = hashlib.sha256(mpk).hexdigest()
        self.wallets[wallet] = (password, iv, wallet_id)
        nonce = self.get_nonce(wallet)
        self.logger.info(f"wallet {wallet.basename()} nonce is {nonce}")
        # If there is an auth token we can try to actually start syncing
        asyncio.run_coroutine_threadsafe(self.pull_safe_thread(wallet, False), wallet.network.asyncio_loop)

    def stop_wallet(self, wallet):
        self.wallets.pop(wallet, None)
