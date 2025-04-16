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
import ssl
import time
from contextlib import asynccontextmanager

import electrum_ecc as ecc
import electrum_aionostr as aionostr
from electrum_aionostr.key import PrivateKey
from typing import Dict, TYPE_CHECKING, Union, List, Tuple, Optional

from electrum import util, Transaction
from electrum.crypto import sha256
from electrum.i18n import _
from electrum.logging import Logger
from electrum.plugin import BasePlugin
from electrum.transaction import PartialTransaction, tx_from_any
from electrum.util import log_exceptions, OldTaskGroup, ca_path, trigger_callback, event_listener
from electrum.wallet import Multisig_Wallet

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet

# event kind used for nostr messages (with expiration tag)
NOSTR_EVENT_KIND = 4

now = lambda: int(time.time())


class PsbtNostrPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.cosigner_wallets = {}  # type: Dict[Abstract_Wallet, CosignerWallet]

    def is_available(self):
        return True

    def add_cosigner_wallet(self, wallet: 'Abstract_Wallet', cosigner_wallet: 'CosignerWallet'):
        assert isinstance(wallet, Multisig_Wallet)
        self.cosigner_wallets[wallet] = cosigner_wallet

    def remove_cosigner_wallet(self, wallet: 'Abstract_Wallet'):
        if cw := self.cosigner_wallets.get(wallet):
            cw.close()
            self.cosigner_wallets.pop(wallet)


class CosignerWallet(Logger):
    # one for each open window (Qt) / open wallet (QML)
    # if user signs a tx, we have the password
    # if user receives a dm? needs to enter password first

    KEEP_DELAY = 24*60*60

    def __init__(self, wallet: 'Multisig_Wallet'):
        assert isinstance(wallet, Multisig_Wallet)
        self.wallet = wallet

        Logger.__init__(self)

        self.network = wallet.network
        self.config = self.wallet.config

        self.pending = asyncio.Event()
        self.wallet_uptodate = asyncio.Event()

        self.known_events = wallet.db.get_dict('cosigner_events')

        for k, v in list(self.known_events.items()):
            if v < now() - self.KEEP_DELAY:
                self.logger.info(f'deleting old event {k}')
                self.known_events.pop(k)
        self.relays = self.config.NOSTR_RELAYS.split(',')
        self.ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        self.logger.info(f'relays {self.relays}')

        self.cosigner_list = []  # type: List[Tuple[str, str]]
        self.nostr_pubkey = None

        for key, keystore in wallet.keystores.items():
            xpub = keystore.get_master_public_key()  # type: str
            privkey = sha256('nostr_psbt:' + xpub)
            pubkey = ecc.ECPrivkey(privkey).get_public_key_bytes()[1:]
            if self.nostr_pubkey is None and not keystore.is_watching_only():
                self.nostr_privkey = privkey.hex()
                self.nostr_pubkey = pubkey.hex()
                self.logger.info(f'nostr pubkey: {self.nostr_pubkey}')
            else:
                self.cosigner_list.append((xpub, pubkey.hex()))

        self.messages = asyncio.Queue()
        self.taskgroup = OldTaskGroup()
        if self.network and self.nostr_pubkey:
            asyncio.run_coroutine_threadsafe(self.main_loop(), self.network.asyncio_loop)

    @event_listener
    def on_event_wallet_updated(self, wallet):
        if self.wallet == wallet and wallet.is_up_to_date() and not self.wallet_uptodate.is_set():
            self.logger.debug('starting handling of PSBTs')
            self.wallet_uptodate.set()

    @log_exceptions
    async def main_loop(self):
        self.logger.info("starting taskgroup.")
        try:
            await self.wallet_uptodate.wait()  # start processing PSBTs only after wallet is_up_to_date
            async with self.taskgroup as group:
                await group.spawn(self.check_direct_messages())
        except Exception as e:
            self.logger.exception("taskgroup died.")
        finally:
            self.logger.info("taskgroup stopped.")

    async def stop(self):
        await self.taskgroup.cancel_remaining()

    @asynccontextmanager
    async def nostr_manager(self):
        manager_logger = self.logger.getChild('aionostr')
        manager_logger.setLevel("INFO")  # set to INFO because DEBUG is very spammy
        async with aionostr.Manager(
                relays=self.relays,
                private_key=self.nostr_privkey,
                ssl_context=self.ssl_context,
                # todo: add proxy support, first needs:
                # https://github.com/spesmilo/electrum-aionostr/pull/8
                proxy=None,
                log=manager_logger
        ) as manager:
            yield manager

    @log_exceptions
    async def send_direct_messages(self, messages: List[Tuple[str, str]]):
        our_private_key: PrivateKey = aionostr.key.PrivateKey(bytes.fromhex(self.nostr_privkey))
        async with self.nostr_manager() as manager:
            for pubkey, msg in messages:
                encrypted_msg: str = our_private_key.encrypt_message(msg, pubkey)
                eid = await aionostr._add_event(
                    manager,
                    kind=NOSTR_EVENT_KIND,
                    content=encrypted_msg,
                    private_key=self.nostr_privkey,
                    tags=[['p', pubkey], ['expiration', str(int(now() + self.KEEP_DELAY))]])
                self.logger.info(f'message sent to {pubkey}: {eid}')

    @log_exceptions
    async def check_direct_messages(self):
        privkey = PrivateKey(bytes.fromhex(self.nostr_privkey))
        async with self.nostr_manager() as manager:
            await manager.connect()
            query = {
                "kinds": [NOSTR_EVENT_KIND],
                "limit": 100,
                "#p": [self.nostr_pubkey],
                "since": int(now() - self.KEEP_DELAY),
            }
            async for event in manager.get_events(query, single_event=False, only_stored=False):
                if event.id in self.known_events:
                    self.logger.info(f'known event {event.id} {util.age(event.created_at)}')
                    continue
                if event.created_at > now() + self.KEEP_DELAY:
                    # might be malicious
                    continue
                if event.created_at < now() - self.KEEP_DELAY:
                    continue
                self.logger.info(f'new event {event.id}')
                try:
                    message = privkey.decrypt_message(event.content, event.pubkey)
                except Exception as e:
                    self.logger.info(f'could not decrypt message {event.pubkey}')
                    self.known_events[event.id] = now()
                    continue
                try:
                    tx = tx_from_any(message)
                except Exception as e:
                    self.logger.info(_("Unable to deserialize the transaction:") + "\n" + str(e))
                    self.known_events[event.id] = now()
                    continue
                self.logger.info(f"received PSBT from {event.pubkey}")
                trigger_callback('psbt_nostr_received', self.wallet, event.pubkey, event.id, tx)
                await self.pending.wait()
                self.pending.clear()

    def diagnostic_name(self):
        return self.wallet.diagnostic_name()

    def close(self):
        self.logger.info("shutting down listener")
        asyncio.run_coroutine_threadsafe(self.stop(), self.network.asyncio_loop)

    def cosigner_can_sign(self, tx: Transaction, cosigner_xpub: str) -> bool:
        # TODO implement this properly:
        #      should return True iff cosigner (with given xpub) can sign and has not yet signed.
        #      note that tx could also be unrelated from wallet?... (not ismine inputs)
        return True

    def can_send_psbt(self, tx: Union[Transaction, PartialTransaction]) -> bool:
        if tx.is_complete() or self.wallet.can_sign(tx):
            return False
        for xpub, pubkey in self.cosigner_list:
            if self.cosigner_can_sign(tx, xpub):
                return True
        return False

    def mark_pending_event_rcvd(self, event_id):
        self.logger.debug('marking event rcvd')
        self.known_events[event_id] = now()
        self.pending.set()

    def prepare_messages(self, tx: Union[Transaction, PartialTransaction]) -> List[Tuple[str, str]]:
        messages = []
        for xpub, pubkey in self.cosigner_list:
            if not self.cosigner_can_sign(tx, xpub):
                continue
            raw_tx_bytes = tx.serialize_as_bytes()
            messages.append((pubkey, raw_tx_bytes.hex()))
        return messages

    def send_psbt(self, tx: Union[Transaction, PartialTransaction]):
        self.do_send(self.prepare_messages(tx), tx.txid())

    def do_send(self, messages: List[Tuple[str, str]], txid: Optional[str] = None):
        raise NotImplementedError()

    def on_receive(self, pubkey, event_id, tx):
        raise NotImplementedError()

    def add_transaction_to_wallet(self, tx, *, on_failure=None, on_success=None):
        try:
            # TODO: adding tx should be handled more gracefully here:
            # 1) don't replace tx with same tx with less signatures
            # 2) we could combine signatures if tx will become more complete
            # 3) ... more heuristics?
            if not self.wallet.adb.add_transaction(tx):
                # TODO: instead of bool return value, we could use specific fail reason exceptions here
                raise Exception('transaction was not added')
        except Exception as e:
            if on_failure:
                on_failure(str(e))
        else:
            self.wallet.save_db()
            if on_success:
                on_success()
