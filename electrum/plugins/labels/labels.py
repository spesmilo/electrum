import asyncio
import hashlib
import json
import sys
import traceback

import base64

from electrum.plugin import BasePlugin, hook
from electrum.crypto import aes_encrypt_with_iv, aes_decrypt_with_iv
from electrum.i18n import _
from electrum.util import log_exceptions, ignore_exceptions, make_aiohttp_session

class LabelsPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.target_host = 'labels.electrum.org'
        self.wallets = {}
        self.proxy = None

    def encode(self, wallet, msg):
        password, iv, wallet_id = self.wallets[wallet]
        encrypted = aes_encrypt_with_iv(password, iv, msg.encode('utf8'))
        return base64.b64encode(encrypted).decode()

    def decode(self, wallet, message):
        password, iv, wallet_id = self.wallets[wallet]
        decoded = base64.b64decode(message)
        decrypted = aes_decrypt_with_iv(password, iv, decoded)
        return decrypted.decode('utf8')

    def get_nonce(self, wallet):
        # nonce is the nonce to be used with the next change
        nonce = wallet.storage.get('wallet_nonce')
        if nonce is None:
            nonce = 1
            self.set_nonce(wallet, nonce)
        return nonce

    def set_nonce(self, wallet, nonce):
        self.print_error("set", wallet.basename(), "nonce to", nonce)
        wallet.storage.put("wallet_nonce", nonce)

    @hook
    def set_label(self, wallet, item, label):
        if wallet not in self.wallets:
            return
        if not item:
            return
        nonce = self.get_nonce(wallet)
        wallet_id = self.wallets[wallet][2]
        bundle = {"walletId": wallet_id,
                  "walletNonce": nonce,
                  "externalId": self.encode(wallet, item),
                  "encryptedLabel": self.encode(wallet, label)}
        asyncio.run_coroutine_threadsafe(self.do_post_safe("/label", bundle), wallet.network.asyncio_loop)
        # Caller will write the wallet
        self.set_nonce(wallet, nonce + 1)

    @ignore_exceptions
    @log_exceptions
    async def do_post_safe(self, *args):
        await self.do_post(*args)

    async def do_get(self, url = "/labels"):
        url = 'https://' + self.target_host + url
        async with make_aiohttp_session(self.proxy) as session:
            async with session.get(url) as result:
                return await result.json()

    async def do_post(self, url = "/labels", data=None):
        url = 'https://' + self.target_host + url
        async with make_aiohttp_session(self.proxy) as session:
            async with session.post(url, json=data) as result:
                try:
                    return await result.json()
                except Exception as e:
                    raise Exception('Could not decode: ' + await result.text()) from e

    async def push_thread(self, wallet):
        wallet_data = self.wallets.get(wallet, None)
        if not wallet_data:
            raise Exception('Wallet {} not loaded'.format(wallet))
        wallet_id = wallet_data[2]
        bundle = {"labels": [],
                  "walletId": wallet_id,
                  "walletNonce": self.get_nonce(wallet)}
        for key, value in wallet.labels.items():
            try:
                encoded_key = self.encode(wallet, key)
                encoded_value = self.encode(wallet, value)
            except:
                self.print_error('cannot encode', repr(key), repr(value))
                continue
            bundle["labels"].append({'encryptedLabel': encoded_value,
                                     'externalId': encoded_key})
        await self.do_post("/labels", bundle)

    async def pull_thread(self, wallet, force):
        wallet_data = self.wallets.get(wallet, None)
        if not wallet_data:
            raise Exception('Wallet {} not loaded'.format(wallet))
        wallet_id = wallet_data[2]
        nonce = 1 if force else self.get_nonce(wallet) - 1
        self.print_error("asking for labels since nonce", nonce)
        response = await self.do_get("/labels/since/%d/for/%s" % (nonce, wallet_id))
        if response["labels"] is None:
            self.print_error('no new labels')
            return
        result = {}
        for label in response["labels"]:
            try:
                key = self.decode(wallet, label["externalId"])
                value = self.decode(wallet, label["encryptedLabel"])
            except:
                continue
            try:
                json.dumps(key)
                json.dumps(value)
            except:
                self.print_error('error: no json', key)
                continue
            result[key] = value

        for key, value in result.items():
            if force or not wallet.labels.get(key):
                wallet.labels[key] = value

        self.print_error("received %d labels" % len(response))
        # do not write to disk because we're in a daemon thread
        wallet.storage.put('labels', wallet.labels)
        self.set_nonce(wallet, response["nonce"] + 1)
        self.on_pulled(wallet)

    @ignore_exceptions
    @log_exceptions
    async def pull_safe_thread(self, wallet, force):
        await self.pull_thread(wallet, force)

    def pull(self, wallet, force):
        if not wallet.network: raise Exception(_('You are offline.'))
        return asyncio.run_coroutine_threadsafe(self.pull_thread(wallet, force), wallet.network.asyncio_loop).result()

    def push(self, wallet):
        if not wallet.network: raise Exception(_('You are offline.'))
        return asyncio.run_coroutine_threadsafe(self.push_thread(wallet), wallet.network.asyncio_loop).result()

    def start_wallet(self, wallet):
        if not wallet.network: return  # 'offline' mode
        nonce = self.get_nonce(wallet)
        self.print_error("wallet", wallet.basename(), "nonce is", nonce)
        mpk = wallet.get_fingerprint()
        if not mpk:
            return
        mpk = mpk.encode('ascii')
        password = hashlib.sha1(mpk).hexdigest()[:32].encode('ascii')
        iv = hashlib.sha256(password).digest()[:16]
        wallet_id = hashlib.sha256(mpk).hexdigest()
        self.wallets[wallet] = (password, iv, wallet_id)
        # If there is an auth token we can try to actually start syncing
        asyncio.run_coroutine_threadsafe(self.pull_safe_thread(wallet, False), wallet.network.asyncio_loop)
        self.proxy = wallet.network.proxy
        wallet.network.register_callback(self.set_proxy, ['proxy_set'])

    def stop_wallet(self, wallet):
        if not wallet.network: return  # 'offline' mode
        wallet.network.unregister_callback('proxy_set')
        self.wallets.pop(wallet, None)

    def set_proxy(self, evt_name, new_proxy):
        self.proxy = new_proxy
        self.print_error("proxy set")
