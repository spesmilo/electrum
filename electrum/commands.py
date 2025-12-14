#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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
import io
import sys
import datetime
import time
import argparse
import json
import ast
import binascii
import base64
import asyncio
import inspect
from asyncio import CancelledError
from collections import defaultdict
from functools import wraps
from decimal import Decimal, InvalidOperation
from typing import Optional, TYPE_CHECKING, Dict, List, Any, Union
import os
import re

import electrum_ecc as ecc

from . import util
from .lnmsg import OnionWireSerializer
from .lnworker import LN_P2P_NETWORK_TIMEOUT
from .logging import Logger
from .onion_message import create_blinded_path, send_onion_message_to
from .submarine_swaps import NostrTransport
from .util import (
    bfh, json_decode, json_normalize, is_hash256_str, is_hex_str, to_bytes, parse_max_spend, to_decimal,
    UserFacingException, InvalidPassword
)
from . import bitcoin
from .bitcoin import is_address,  hash_160, COIN
from .bip32 import BIP32Node
from .i18n import _
from .transaction import (
    Transaction, multisig_script, PartialTransaction, PartialTxOutput, tx_from_any, PartialTxInput, TxOutpoint,
    convert_raw_tx_to_hex
)
from . import transaction
from .invoices import Invoice, PR_PAID, PR_UNPAID, PR_EXPIRED
from .synchronizer import Notifier
from .wallet import (
    Abstract_Wallet, create_new_wallet, restore_wallet_from_text, Deterministic_Wallet, BumpFeeStrategy,
    Imported_Wallet
)
from .address_synchronizer import TX_HEIGHT_LOCAL
from .mnemonic import Mnemonic
from .lnutil import (channel_id_from_funding_tx, LnFeatures, SENT, RECEIVED, MIN_FINAL_CLTV_DELTA_ACCEPTED,
                     PaymentFeeBudget, NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE)
from .plugin import run_hook, DeviceMgr, Plugins
from .version import ELECTRUM_VERSION
from .simple_config import SimpleConfig
from .fee_policy import FeePolicy, FEE_ETA_TARGETS, FEERATE_DEFAULT_RELAY
from . import GuiImportError
from . import crypto
from . import constants
from . import descriptor

if TYPE_CHECKING:
    from .network import Network
    from .daemon import Daemon
    from electrum.lnworker import PaymentInfo


known_commands = {}  # type: Dict[str, Command]


class NotSynchronizedException(UserFacingException):
    pass


def satoshis_or_max(amount):
    return satoshis(amount) if not parse_max_spend(amount) else amount


def satoshis(amount):
    # satoshi conversion must not be performed by the parser
    return int(COIN*to_decimal(amount)) if amount is not None else None


def format_satoshis(x: Union[float, int, Decimal, None]) -> Optional[str]:
    """
    input: satoshis as a Number
    output: str formatted as bitcoin amount
    """
    if x is None:
        return None
    return util.format_satoshis_plain(x, is_max_allowed=False)


class Command:
    def __init__(self, func, name, s):
        self.name = name
        self.requires_network = 'n' in s  # better name would be "requires daemon"
        self.requires_wallet = 'w' in s
        self.requires_password = 'p' in s
        self.requires_lightning = 'l' in s
        self.parse_docstring(func.__doc__)
        varnames = func.__code__.co_varnames[1:func.__code__.co_argcount]
        self.defaults = func.__defaults__
        if self.defaults:
            n = len(self.defaults)
            self.params = list(varnames[:-n])
            self.options = list(varnames[-n:])
        else:
            self.params = list(varnames)
            self.options = []
            self.defaults = []

        # sanity checks
        if self.requires_password:
            assert self.requires_wallet
        for varname in ('wallet_path', 'wallet'):
            if varname in varnames:
                assert varname in self.options, f"cmd: {self.name}: {varname} not in options {self.options}"
        assert not ('wallet_path' in varnames and 'wallet' in varnames)
        if self.requires_wallet:
            assert 'wallet' in varnames

    def parse_docstring(self, docstring):
        docstring = docstring or ''
        docstring = docstring.strip()
        self.description = docstring
        self.arg_descriptions = {}
        self.arg_types = {}
        for x in re.finditer(r'arg:(.*?):(.*?):(.*)$', docstring, flags=re.MULTILINE):
            self.arg_descriptions[x.group(2)] = x.group(3)
            self.arg_types[x.group(2)] = x.group(1)
            self.description = self.description.replace(x.group(), '')
        self.short_description = self.description.split('.')[0]


def command(s):
    def decorator(func):
        if hasattr(func, '__wrapped__'):
            # plugin command function
            name = func.plugin_name + '_' + func.__name__
            known_commands[name] = Command(func.__wrapped__, name, s)
        else:
            # regular command function
            name = func.__name__
            known_commands[name] = Command(func, name, s)

        @wraps(func)
        async def func_wrapper(*args, **kwargs):
            cmd_runner = args[0]  # type: Commands
            cmd = known_commands[name]  # type: Command
            password = kwargs.get('password')
            daemon = cmd_runner.daemon
            if daemon:
                if 'wallet_path' in cmd.options or cmd.requires_wallet:
                    kwargs['wallet_path'] = daemon.config.maybe_complete_wallet_path(kwargs.get('wallet_path'))
                if 'wallet' in cmd.options:
                    wallet_path = kwargs.pop('wallet_path', None) # unit tests may set wallet and not wallet_path
                    wallet = kwargs.get('wallet', None)           # run_offline_command sets both
                    if wallet is None and wallet_path is not None:
                        wallet = daemon.get_wallet(wallet_path)
                        if wallet is None:
                            raise UserFacingException('wallet not loaded')
                        kwargs['wallet'] = wallet
                    if cmd.requires_password and password is None and wallet and wallet.has_password():
                        password = wallet.get_unlocked_password()
                        if password:
                            kwargs['password'] = password
                        else:
                            raise UserFacingException('Password required. Unlock the wallet, or add a --password option to your command')
            wallet = kwargs.get('wallet')  # type: Optional[Abstract_Wallet]
            if cmd.requires_wallet and not wallet:
                raise UserFacingException('wallet not loaded')
            if cmd.requires_password and wallet.has_password():
                if password is None:
                    raise UserFacingException('Password required')
                try:
                    wallet.check_password(password)
                except InvalidPassword as e:
                    raise UserFacingException(str(e)) from None
            if cmd.requires_lightning and (not wallet or not wallet.has_lightning()):
                raise UserFacingException('Lightning not enabled in this wallet')
            return await func(*args, **kwargs)
        return func_wrapper
    return decorator


class Commands(Logger):

    def __init__(self, *, config: 'SimpleConfig',
                 network: 'Network' = None,
                 daemon: 'Daemon' = None, callback=None):
        Logger.__init__(self)
        self.config = config
        self.daemon = daemon
        self.network = network
        self._callback = callback

    def _run(self, method, args, password_getter=None, **kwargs):
        """This wrapper is called from unit tests and the Qt python console."""
        cmd = known_commands[method]
        password = kwargs.get('password', None)
        wallet = kwargs.get('wallet', None)
        if (cmd.requires_password and wallet and wallet.has_password()
                and password is None):
            password = password_getter()
            if password is None:
                return

        f = getattr(self, method)
        if cmd.requires_password:
            kwargs['password'] = password

        if 'wallet' in kwargs:
            sig = inspect.signature(f)
            if 'wallet' not in sig.parameters:
                kwargs.pop('wallet')

        coro = f(*args, **kwargs)
        fut = asyncio.run_coroutine_threadsafe(coro, util.get_asyncio_loop())
        result = fut.result()

        if self._callback:
            self._callback()
        return result

    @command('n')
    async def getinfo(self):
        """ network info """
        net_params = self.network.get_parameters()
        response = {
            'network': constants.net.NET_NAME,
            'path': self.network.config.path,
            'server': net_params.server.host,
            'blockchain_height': self.network.get_local_height(),
            'server_height': self.network.get_server_height(),
            'spv_nodes': len(self.network.get_interfaces()),
            'connected': self.network.is_connected(),
            'auto_connect': net_params.auto_connect,
            'version': ELECTRUM_VERSION,
            'fee_estimates': self.network.fee_estimates.get_data()
        }
        return response

    @command('n')
    async def stop(self):
        """Stop daemon"""
        await self.daemon.stop()
        return "Daemon stopped"

    @command('n')
    async def list_wallets(self):
        """List wallets open in daemon"""
        return [
            {
                'path': w.db.storage.path,
                'synchronized': w.is_up_to_date(),
                'unlocked': not w.has_password() or (w.get_unlocked_password() is not None),
            }
            for w in self.daemon.get_wallets().values()
        ]

    @command('n')
    async def load_wallet(self, wallet_path=None, password=None):
        """
        Load the wallet in memory
        """
        wallet = self.daemon.load_wallet(wallet_path, password, upgrade=True)
        if wallet is None:
            raise UserFacingException('could not load wallet')
        run_hook('load_wallet', wallet, None)
        return wallet_path

    @command('n')
    async def close_wallet(self, wallet_path=None):
        """Close wallet"""
        return await self.daemon._stop_wallet(wallet_path)

    @command('')
    async def create(self, passphrase=None, password=None, encrypt_file=True, seed_type=None, wallet_path=None, use_levelDB=False):
        """Create a new wallet.
        If you want to be prompted for an argument, type '?' or ':' (concealed)

        arg:str:passphrase:Seed extension
        arg:str:seed_type:The type of wallet to create, e.g. 'standard' or 'segwit'
        arg:bool:encrypt_file:Whether the file on disk should be encrypted with the provided password
        arg:bool:use_levelDB:Create levelDB storage
        """
        d = create_new_wallet(
            path=wallet_path,
            passphrase=passphrase,
            password=password,
            encrypt_file=encrypt_file,
            seed_type=seed_type,
            use_levelDB=use_levelDB,
            config=self.config)
        return {
            'seed': d['seed'],
            'path': d['wallet'].storage.path,
            'msg': d['msg'],
        }

    @command('')
    async def restore(self, text, passphrase=None, password=None, encrypt_file=True, wallet_path=None, use_levelDB=False):
        """Restore a wallet from text. Text can be a seed phrase, a master
        public key, a master private key, a list of bitcoin addresses
        or bitcoin private keys.
        If you want to be prompted for an argument, type '?' or ':' (concealed)

        arg:str:text:seed phrase
        arg:str:passphrase:Seed extension
        arg:bool:encrypt_file:Whether the file on disk should be encrypted with the provided password
        arg:bool:use_levelDB:Create levelDB storage
        """
        # TODO create a separate command that blocks until wallet is synced
        d = restore_wallet_from_text(
            text,
            path=wallet_path,
            passphrase=passphrase,
            password=password,
            encrypt_file=encrypt_file,
            use_levelDB=use_levelDB,
            config=self.config)
        return {
            'path': d['wallet'].storage.path,
            'msg': d['msg'],
        }

    @command('wp')
    async def password(self, password=None, new_password=None, encrypt_file=None, wallet: Abstract_Wallet = None):
        """
        Change wallet password.

        arg:bool:encrypt_file:Whether the file on disk should be encrypted with the provided password (default=true)
        arg:str:new_password:New Password
        """
        if wallet.storage.is_encrypted_with_hw_device() and new_password:
            raise UserFacingException("Can't change the password of a wallet encrypted with a hw device.")
        if encrypt_file is None:
            if not password and new_password:
                # currently no password, setting one now: we encrypt by default
                encrypt_file = True
            else:
                encrypt_file = wallet.storage.is_encrypted()
        wallet.update_password(password, new_password, encrypt_storage=encrypt_file)
        wallet.save_db()
        return {'password': wallet.has_password()}

    @command('w')
    async def get(self, key, wallet: Abstract_Wallet = None):
        """
        Return item from wallet storage

        arg:str:key:storage key
        """
        return wallet.db.get(key)

    @command('')
    async def getconfig(self, key):
        """Return the current value of a configuration variable.

        arg:str:key:name of the configuration variable
        """
        if Plugins.is_plugin_enabler_config_key(key):
            return self.config.get(key)
        else:
            cv = self.config.cv.from_key(key)
            return cv.get()

    @classmethod
    def _setconfig_normalize_value(cls, key, value):
        if key not in (SimpleConfig.RPC_USERNAME.key(), SimpleConfig.RPC_PASSWORD.key()):
            value = json_decode(value)
            # call literal_eval for backward compatibility (see #4225)
            try:
                value = ast.literal_eval(value)
            except Exception:
                pass
        return value

    def _setconfig(self, key, value):
        value = self._setconfig_normalize_value(key, value)
        if self.daemon and key == SimpleConfig.RPC_USERNAME.key():
            self.daemon.commands_server.rpc_user = value
        if self.daemon and key == SimpleConfig.RPC_PASSWORD.key():
            self.daemon.commands_server.rpc_password = value
        if Plugins.is_plugin_enabler_config_key(key):
            self.config.set_key(key, value)
        else:
            cv = self.config.cv.from_key(key)
            cv.set(value)

    @command('')
    async def setconfig(self, key, value):
        """
        Set a configuration variable.

        arg:str:key:name of the configuration variable
        arg:str:value:value. may be a string or a Python expression.
        """
        self._setconfig(key, value)

    @command('')
    async def unsetconfig(self, key):
        """
        Clear a configuration variable.
        The variable will be reset to its default value.

        arg:str:key:name of the configuration variable
        """
        self._setconfig(key, None)

    @command('')
    async def listconfig(self):
        """Returns the list of all configuration variables. """
        return self.config.list_config_vars()

    @command('')
    async def helpconfig(self, key):
        """Returns help about a configuration variable.

        arg:str:key:name of the configuration variable
        """
        cv = self.config.cv.from_key(key)
        short = cv.get_short_desc()
        long = cv.get_long_desc()
        if short and long:
            return short + "\n---\n\n" + long
        elif short or long:
            return short or long
        else:
            return f"No description available for '{key}'"

    @command('')
    async def make_seed(self, nbits=None, language=None, seed_type=None):
        """
        Create a seed

        arg:int:nbits:Number of bits of entropy
        arg:str:seed_type:The type of seed to create, e.g. 'standard' or 'segwit'
        arg:str:language:Default language for wordlist
        """
        s = Mnemonic(language).make_seed(seed_type=seed_type, num_bits=nbits)
        return s

    @command('n')
    async def getaddresshistory(self, address):
        """
        Return the transaction history of any address. Note: This is a
        walletless server query, results are not checked by SPV.

        arg:str:address:Bitcoin address
        """
        sh = bitcoin.address_to_scripthash(address)
        return await self.network.get_history_for_scripthash(sh)

    @command('wp')
    async def unlock(self, wallet: Abstract_Wallet = None, password=None):
        """Unlock the wallet (store the password in memory)."""
        wallet.unlock(password)

    @command('w')
    async def listunspent(self, wallet: Abstract_Wallet = None):
        """List unspent outputs. Returns the list of unspent transaction
        outputs in your wallet."""
        coins = []
        for txin in wallet.get_utxos():
            d = txin.to_json()
            v = d.pop("value_sats")
            d["value"] = format_satoshis(v)
            coins.append(d)
        return coins

    @command('n')
    async def getaddressunspent(self, address):
        """
        Returns the UTXO list of any address. Note: This
        is a walletless server query, results are not checked by SPV.

        arg:str:address:Bitcoin address
        """
        sh = bitcoin.address_to_scripthash(address)
        return await self.network.listunspent_for_scripthash(sh)

    @command('')
    async def serialize(self, jsontx):
        """Create a signed raw transaction from a json tx template.

        Example value for "jsontx" arg: {
            "inputs": [
                {"prevout_hash": "9d221a69ca3997cbeaf5624d723e7dc5f829b1023078c177d37bdae95f37c539", "prevout_n": 1,
                 "value_sats": 1000000, "privkey": "p2wpkh:cVDXzzQg6RoCTfiKpe8MBvmm5d5cJc6JLuFApsFDKwWa6F5TVHpD"}
            ],
            "outputs": [
                {"address": "tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd", "value_sats": 990000}
            ]
        }
        arg:json:jsontx:Transaction in json
        """
        keypairs = {}
        inputs = []  # type: List[PartialTxInput]
        locktime = jsontx.get('locktime', 0)
        for txin_idx, txin_dict in enumerate(jsontx.get('inputs')):
            if txin_dict.get('prevout_hash') is not None and txin_dict.get('prevout_n') is not None:
                prevout = TxOutpoint(txid=bfh(txin_dict['prevout_hash']), out_idx=int(txin_dict['prevout_n']))
            elif txin_dict.get('output'):
                prevout = TxOutpoint.from_str(txin_dict['output'])
            else:
                raise UserFacingException(f"missing prevout for txin {txin_idx}")
            txin = PartialTxInput(prevout=prevout)
            try:
                txin._trusted_value_sats = int(txin_dict.get('value') or txin_dict['value_sats'])
            except KeyError:
                raise UserFacingException(f"missing 'value_sats' field for txin {txin_idx}")
            nsequence = txin_dict.get('nsequence', None)
            if nsequence is not None:
                txin.nsequence = nsequence
            sec = txin_dict.get('privkey')
            if sec:
                txin_type, privkey, compressed = bitcoin.deserialize_privkey(sec)
                pubkey = ecc.ECPrivkey(privkey).get_public_key_bytes(compressed=compressed)
                keypairs[pubkey] = privkey
                desc = descriptor.get_singlesig_descriptor_from_legacy_leaf(pubkey=pubkey.hex(), script_type=txin_type)
                txin.script_descriptor = desc
            inputs.append(txin)

        outputs = []  # type: List[PartialTxOutput]
        for txout_idx, txout_dict in enumerate(jsontx.get('outputs')):
            try:
                txout_addr = txout_dict['address']
            except KeyError:
                raise UserFacingException(f"missing 'address' field for txout {txout_idx}")
            try:
                txout_val = int(txout_dict.get('value') or txout_dict['value_sats'])
            except KeyError:
                raise UserFacingException(f"missing 'value_sats' field for txout {txout_idx}")
            txout = PartialTxOutput.from_address_and_value(txout_addr, txout_val)
            outputs.append(txout)

        tx = PartialTransaction.from_io(inputs, outputs, locktime=locktime)
        tx.sign(keypairs)
        return tx.serialize()

    @command('')
    async def signtransaction_with_privkey(self, tx, privkey):
        """Sign a transaction with private keys passed as parameter.

        arg:tx:tx:Transaction to sign
        arg:str:privkey:private key or list of private keys
        """
        tx = tx_from_any(tx)

        txins_dict = defaultdict(list)
        for txin in tx.inputs():
            txins_dict[txin.address].append(txin)

        if not isinstance(privkey, list):
            privkey = [privkey]

        for priv in privkey:
            txin_type, priv2, compressed = bitcoin.deserialize_privkey(priv)
            pubkey = ecc.ECPrivkey(priv2).get_public_key_bytes(compressed=compressed)
            desc = descriptor.get_singlesig_descriptor_from_legacy_leaf(pubkey=pubkey.hex(), script_type=txin_type)
            address = desc.expand().address()
            if address in txins_dict.keys():
                for txin in txins_dict[address]:
                    txin.script_descriptor = desc
                tx.sign({pubkey: priv2})

        return tx.serialize()

    @command('wp')
    async def signtransaction(self, tx, password=None, wallet: Abstract_Wallet = None, ignore_warnings: bool=False):
        """
        Sign a transaction with the current wallet.

        arg:tx:tx:transaction
        arg:bool:ignore_warnings:ignore warnings
        """
        tx = tx_from_any(tx)
        wallet.sign_transaction(tx, password, ignore_warnings=ignore_warnings)
        return tx.serialize()

    @command('')
    async def deserialize(self, tx):
        """
        Deserialize a transaction

        arg:str:tx:Serialized transaction
        """
        tx = tx_from_any(tx)
        return tx.to_json()

    @command('n')
    async def broadcast(self, tx):
        """
        Broadcast a transaction to the network.

        arg:str:tx:Serialized transaction (must be hexadecimal)
        """
        tx = Transaction(tx)
        await self.network.broadcast_transaction(tx)
        return tx.txid()

    @command('')
    async def createmultisig(self, num, pubkeys):
        """
        Create multisig 'n of m' address

        arg:int:num:Number of cosigners required
        arg:json:pubkeys:List of public keys
        """
        assert isinstance(pubkeys, list), (type(num), type(pubkeys))
        redeem_script = multisig_script(pubkeys, num)
        address = bitcoin.hash160_to_p2sh(hash_160(redeem_script))
        return {'address': address, 'redeemScript': redeem_script.hex()}

    @command('w')
    async def freeze(self, address: str, wallet: Abstract_Wallet = None):
        """
        Freeze address. Freeze the funds at one of your wallet\'s addresses

        arg:str:address:Bitcoin address
        """
        return wallet.set_frozen_state_of_addresses([address], True)

    @command('w')
    async def unfreeze(self, address: str, wallet: Abstract_Wallet = None):
        """
        Unfreeze address. Unfreeze the funds at one of your wallet\'s address

        arg:str:address:Bitcoin address
        """
        return wallet.set_frozen_state_of_addresses([address], False)

    @command('w')
    async def freeze_utxo(self, coin: str, wallet: Abstract_Wallet = None):
        """
        Freeze a UTXO so that the wallet will not spend it.

        arg:str:coin:outpoint, in the <txid:index> format
        """
        wallet.set_frozen_state_of_coins([coin], True)
        return True

    @command('w')
    async def unfreeze_utxo(self, coin: str, wallet: Abstract_Wallet = None):
        """Unfreeze a UTXO so that the wallet might spend it.

        arg:str:coin:outpoint
        """
        wallet.set_frozen_state_of_coins([coin], False)
        return True

    @command('wp')
    async def getprivatekeys(self, address, password=None, wallet: Abstract_Wallet = None):
        """
        Get private keys of addresses. You may pass a single wallet address, or a list of wallet addresses.

        arg:str:address:Bitcoin address
        """
        if isinstance(address, str):
            address = address.strip()
        if is_address(address):
            return wallet.export_private_key(address, password)
        domain = address
        return [wallet.export_private_key(address, password) for address in domain]

    @command('wp')
    async def getprivatekeyforpath(self, path, password=None, wallet: Abstract_Wallet = None):
        """Get private key corresponding to derivation path (address index).

        arg:str:path:Derivation path. Can be either a str such as "m/0/50", or a list of ints such as [0, 50].
        """
        return wallet.export_private_key_for_path(path, password)

    @command('w')
    async def ismine(self, address, wallet: Abstract_Wallet = None):
        """
        Check if address is in wallet. Return true if and only address is in wallet

        arg:str:address:Bitcoin address
        """
        return wallet.is_mine(address)

    @command('')
    async def dumpprivkeys(self):
        """Deprecated."""
        return "This command is deprecated. Use a pipe instead: 'electrum listaddresses | electrum getprivatekeys - '"

    @command('')
    async def validateaddress(self, address):
        """Check that an address is valid.

        arg:str:address:Bitcoin address
        """
        return is_address(address)

    @command('w')
    async def getpubkeys(self, address, wallet: Abstract_Wallet = None):
        """
        Return the public keys for a wallet address.

        arg:str:address:Bitcoin address
        """
        return wallet.get_public_keys(address)

    @command('w')
    async def getbalance(self, wallet: Abstract_Wallet = None):
        """Return the balance of your wallet. """
        c, u, x = wallet.get_balance()
        l = wallet.lnworker.get_balance() if wallet.lnworker else None
        out = {"confirmed": format_satoshis(c)}
        if u:
            out["unconfirmed"] = format_satoshis(u)
        if x:
            out["unmatured"] = format_satoshis(x)
        if l:
            out["lightning"] = format_satoshis(l)
        return out

    @command('n')
    async def getaddressbalance(self, address):
        """
        Return the balance of any address. Note: This is a walletless
        server query, results are not checked by SPV.

        arg:str:address:Bitcoin address
        """
        sh = bitcoin.address_to_scripthash(address)
        out = await self.network.get_balance_for_scripthash(sh)
        out["confirmed"] = format_satoshis(out["confirmed"])
        out["unconfirmed"] = format_satoshis(out["unconfirmed"])
        return out

    @command('n')
    async def getmerkle(self, txid, height):
        """Get Merkle branch of a transaction included in a block. Electrum
        uses this to verify transactions (Simple Payment Verification).

        arg:txid:txid:Transaction ID
        arg:int:height:Block height
        """
        return await self.network.get_merkle_for_transaction(txid, int(height))

    @command('n')
    async def getservers(self):
        """Return the list of known servers (candidates for connecting)."""
        return self.network.get_servers()

    @command('')
    async def version(self):
        """Return the version of Electrum."""
        return ELECTRUM_VERSION

    @command('')
    async def version_info(self):
        """Return information about dependencies, such as their version and path."""
        ret = {
            "electrum.version": ELECTRUM_VERSION,
            "electrum.path": os.path.dirname(os.path.realpath(__file__)),
            "python.version": sys.version,
            "python.path": sys.executable,
        }
        # add currently running GUI
        if self.daemon and self.daemon.gui_object:
            ret.update(self.daemon.gui_object.version_info())
        # always add Qt GUI, so we get info even when running this from CLI
        try:
            from .gui.qt import ElectrumGui as QtElectrumGui
            ret.update(QtElectrumGui.version_info())
        except GuiImportError:
            pass
        # Add shared libs (.so/.dll), and non-pure-python dependencies.
        # Such deps can be installed in various ways - often via the Linux distro's pkg manager,
        # instead of using pip, hence it is useful to list them for debugging.
        from electrum_ecc import ecc_fast
        ret.update(ecc_fast.version_info())
        from . import qrscanner
        ret.update(qrscanner.version_info())
        ret.update(DeviceMgr.version_info())
        ret.update(crypto.version_info())
        # add some special cases
        import aiohttp
        ret["aiohttp.version"] = aiohttp.__version__
        import aiorpcx
        ret["aiorpcx.version"] = aiorpcx._version_str
        import certifi
        ret["certifi.version"] = certifi.__version__
        import dns
        ret["dnspython.version"] = dns.__version__
        import ssl
        ret["openssl.version"] = ssl.OPENSSL_VERSION

        return ret

    @command('w')
    async def getmpk(self, wallet: Abstract_Wallet = None):
        """Get master public key. Return your wallet\'s master public key"""
        return wallet.get_master_public_key()

    @command('wp')
    async def getmasterprivate(self, password=None, wallet: Abstract_Wallet = None):
        """Get master private key. Return your wallet\'s master private key"""
        return str(wallet.keystore.get_master_private_key(password))

    @command('')
    async def convert_xkey(self, xkey, xtype):
        """Convert xtype of a master key. e.g. xpub -> ypub

        arg:str:xkey:the key
        arg:str:xtype:the type, eg 'xpub'
        """
        try:
            node = BIP32Node.from_xkey(xkey)
        except Exception:
            raise UserFacingException('xkey should be a master public/private key')
        return node._replace(xtype=xtype).to_xkey()

    @command('wp')
    async def getseed(self, password=None, wallet: Abstract_Wallet = None):
        """Get seed phrase. Print the generation seed of your wallet."""
        s = wallet.get_seed(password)
        return s

    @command('wp')
    async def importprivkey(self, privkey, password=None, wallet: Abstract_Wallet = None):
        """Import a private key or a list of private keys.

        arg:str:privkey:Private key. Type \'?\' to get a prompt.
        """
        if not wallet.can_import_privkey():
            return "Error: This type of wallet cannot import private keys. Try to create a new wallet with that key."
        assert isinstance(wallet, Imported_Wallet)
        keys = privkey.split()
        if not keys:
            return "Error: no keys given"
        elif len(keys) == 1:
            try:
                addr = wallet.import_private_key(keys[0], password)
                out = "Keypair imported: " + addr
            except Exception as e:
                out = "Error: " + repr(e)
            return out
        else:
            good_inputs, bad_inputs = wallet.import_private_keys(keys, password)
            return {
                "good_keys": len(good_inputs),
                "bad_keys": len(bad_inputs),
            }

    async def _resolver(self, x, wallet: Abstract_Wallet):
        if x is None:
            return None
        out = await wallet.contacts.resolve(x)
        return out['address']

    @command('n')
    async def sweep(self, privkey, destination, fee=None, feerate=None, imax=100):
        """
        Sweep private keys. Returns a transaction that spends UTXOs from
        privkey to a destination address. The transaction will not be broadcast.

        arg:str:privkey:Private key. Type \'?\' to get a prompt.
        arg:str:destination:Bitcoin address, contact or alias
        arg:decimal:fee:Transaction fee (absolute, in BTC)
        arg:decimal:feerate:Transaction fee rate (in sat/vbyte)
        arg:int:imax:Maximum number of inputs
        """
        from .wallet import sweep
        fee_policy = self._get_fee_policy(fee, feerate)
        privkeys = privkey.split()
        #dest = self._resolver(destination)
        tx = await sweep(
            privkeys,
            network=self.network,
            to_address=destination,
            fee_policy=fee_policy,
            imax=imax,
        )
        return tx.serialize() if tx else None

    @command('wp')
    async def signmessage(self, address, message, password=None, wallet: Abstract_Wallet = None):
        """Sign a message with a key. Use quotes if your message contains
        whitespaces

        arg:str:address:Bitcoin address
        arg:str:message:Clear text message. Use quotes if it contains spaces.
        """
        sig = wallet.sign_message(address, message, password)
        return base64.b64encode(sig).decode('ascii')

    @command('')
    async def verifymessage(self, address, signature, message):
        """Verify a signature.

        arg:str:address:Bitcoin address
        arg:str:message:Clear text message. Use quotes if it contains spaces.
        arg:str:signature:The signature, base64-encoded.
        """
        try:
            sig = base64.b64decode(signature, validate=True)
        except binascii.Error:
            return False
        message = util.to_bytes(message)
        return bitcoin.verify_usermessage_with_address(address, sig, message)

    def _get_fee_policy(self, fee: str, feerate: str):
        if fee is not None and feerate is not None:
            raise Exception('Cannot set both fee and feerate')
        if fee is not None:
            fee_sats = satoshis(fee)
            fee_policy = FeePolicy(f'fixed:{fee_sats}')
        elif feerate is not None:
            sat_per_kvbyte = int(1000 * to_decimal(feerate))
            fee_policy = FeePolicy(f'feerate:{sat_per_kvbyte}')
        else:
            fee_policy = FeePolicy(self.config.FEE_POLICY)
        return fee_policy

    @command('wp')
    async def payto(self, destination, amount, fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None,
                    unsigned=False, rbf=True, password=None, locktime=None, addtransaction=False, wallet: Abstract_Wallet = None):
        """Create an on-chain transaction.

        arg:str:destination:Bitcoin address, contact or alias
        arg:decimal_or_max:amount:Amount to be sent (in BTC). Type '!' to send the maximum available.
        arg:decimal:fee:Transaction fee (absolute, in BTC)
        arg:decimal:feerate:Transaction fee rate (in sat/vbyte)
        arg:str:from_addr:Source address (must be a wallet address; use sweep to spend from non-wallet address)
        arg:str:change_addr:Change address. Default is a spare address, or the source address if it's not in the wallet
        arg:bool:rbf:Whether to signal opt-in Replace-By-Fee in the transaction (true/false)
        arg:bool:addtransaction:Whether transaction is to be used for broadcasting afterwards. Adds transaction to the wallet
        arg:int:locktime:Set locktime block number
        arg:bool:unsigned:Do not sign transaction
        arg:json:from_coins:Source coins (must be in wallet; use sweep to spend from non-wallet address)
        """
        return await self.paytomany(
            outputs=[(destination, amount),],
            fee=fee,
            feerate=feerate,
            from_addr=from_addr,
            from_coins=from_coins,
            change_addr=change_addr,
            unsigned=unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime,
            addtransaction=addtransaction,
            wallet=wallet,
        )

    @command('wp')
    async def paytomany(self, outputs, fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None,
                        unsigned=False, rbf=True, password=None, locktime=None, addtransaction=False, wallet: Abstract_Wallet = None):
        """Create a multi-output transaction.

        arg:json:outputs:json list of ["address", "amount in BTC"]
        arg:bool:rbf:Whether to signal opt-in Replace-By-Fee in the transaction (true/false)
        arg:decimal:fee:Transaction fee (absolute, in BTC)
        arg:decimal:feerate:Transaction fee rate (in sat/vbyte)
        arg:str:from_addr:Source address (must be a wallet address; use sweep to spend from non-wallet address)
        arg:str:change_addr:Change address. Default is a spare address, or the source address if it's not in the wallet
        arg:bool:addtransaction:Whether transaction is to be used for broadcasting afterwards. Adds transaction to the wallet
        arg:int:locktime:Set locktime block number
        arg:bool:unsigned:Do not sign transaction
        arg:json:from_coins:Source coins (must be in wallet; use sweep to spend from non-wallet address)
        """
        fee_policy = self._get_fee_policy(fee, feerate)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = await self._resolver(change_addr, wallet)
        if domain_addr is not None:
            resolvers = [self._resolver(addr, wallet) for addr in domain_addr]
            domain_addr = await asyncio.gather(*resolvers)
        final_outputs = []
        for address, amount in outputs:
            address = await self._resolver(address, wallet)
            amount_sat = satoshis_or_max(amount)
            final_outputs.append(PartialTxOutput.from_address_and_value(address, amount_sat))
        coins = wallet.get_spendable_coins(domain_addr)
        if domain_coins is not None:
            coins = [coin for coin in coins if (coin.prevout.to_str() in domain_coins)]
        tx = wallet.make_unsigned_transaction(
            outputs=final_outputs,
            fee_policy=fee_policy,
            change_addr=change_addr,
            coins=coins,
            rbf=rbf,
            locktime=locktime,
        )
        if not unsigned:
            wallet.sign_transaction(tx, password)
        result = tx.serialize()
        if addtransaction:
            await self.addtransaction(result, wallet=wallet)
        return result

    def get_year_timestamps(self, year: int) -> dict[str, Any]:
        kwargs = {}
        if year:
            start_date = datetime.datetime(year, 1, 1)
            end_date = datetime.datetime(year+1, 1, 1)
            kwargs['from_timestamp'] = time.mktime(start_date.timetuple())
            kwargs['to_timestamp'] = time.mktime(end_date.timetuple())
        return kwargs

    @command('w')
    async def onchain_capital_gains(self, year=None, wallet: Abstract_Wallet = None):
        """
        Capital gains, using utxo pricing.
        This cannot be used with lightning.

        arg:int:year:Show cap gains for a given year
        """
        kwargs = self.get_year_timestamps(year)
        from .exchange_rate import FxThread
        fx = self.daemon.fx if self.daemon else FxThread(config=self.config)
        return json_normalize(wallet.get_onchain_capital_gains(fx, **kwargs))

    @command('wp')
    async def bumpfee(self, tx, new_fee_rate, from_coins=None, decrease_payment=False, password=None, unsigned=False, wallet: Abstract_Wallet = None):
        """
        Bump the fee for an unconfirmed transaction.
        'tx' can be either a raw hex tx or a txid. If txid, the corresponding tx must already be part of the wallet history.

        arg:str:tx:Serialized transaction (hexadecimal)
        arg:str:new_fee_rate: The Updated/Increased Transaction fee rate (in sats/vbyte)
        arg:bool:decrease_payment:Whether payment amount will be decreased (true/false)
        arg:bool:unsigned:Do not sign transaction
        arg:json:from_coins:Coins that may be used to inncrease the fee (must be in wallet)
        """
        if is_hash256_str(tx):  # txid
            tx = wallet.db.get_transaction(tx)
            if tx is None:
                raise UserFacingException("Transaction not in wallet.")
        else:  # raw tx
            try:
                tx = Transaction(tx)
                tx.deserialize()
            except transaction.SerializationError as e:
                raise UserFacingException(f"Failed to deserialize transaction: {e}") from e
        domain_coins = from_coins.split(',') if from_coins else None
        coins = wallet.get_spendable_coins(None)
        if domain_coins is not None:
            coins = [coin for coin in coins if (coin.prevout.to_str() in domain_coins)]
        tx.add_info_from_wallet(wallet)
        await tx.add_info_from_network(self.network)
        new_tx = wallet.bump_fee(
            tx=tx,
            coins=coins,
            strategy=BumpFeeStrategy.DECREASE_PAYMENT if decrease_payment else BumpFeeStrategy.PRESERVE_PAYMENT,
            new_fee_rate=new_fee_rate)
        if not unsigned:
            wallet.sign_transaction(new_tx, password)
        return new_tx.serialize()

    @command('w')
    async def onchain_history(
        self, show_fiat=False, year=None, show_addresses=False,
        from_height=None, to_height=None,
        wallet: Abstract_Wallet = None,
    ):
        """Wallet onchain history. Returns the transaction history of your wallet.

        arg:bool:show_addresses:Show input and output addresses
        arg:bool:show_fiat:Show fiat value of transactions
        arg:int:year:Show history for a given year
        arg:int:from_height:Only show transactions that confirmed after(inclusive) given block height
        arg:int:to_height:Only show transactions that confirmed before(exclusive) given block height
        """
        # trigger lnwatcher callbacks for their side effects: setting labels and accounting_addresses
        if not self.network and wallet.lnworker:
            await wallet.lnworker.lnwatcher.trigger_callbacks(requires_synchronizer=False)

        kwargs = self.get_year_timestamps(year)
        kwargs['from_height'] = from_height
        kwargs['to_height'] = to_height
        onchain_history = wallet.get_onchain_history(**kwargs)
        out = [x.to_dict() for x in onchain_history.values()]
        if show_fiat:
            from .exchange_rate import FxThread
            fx = self.daemon.fx if self.daemon else FxThread(config=self.config)
        else:
            fx = None
        for item in out:
            if show_addresses:
                tx = wallet.db.get_transaction(item['txid'])
                item['inputs'] = list(map(lambda x: x.to_json(), tx.inputs()))
                item['outputs'] = list(map(lambda x: {'address': x.get_ui_address_str(), 'value_sat': x.value},
                                           tx.outputs()))
            if fx:
                fiat_fields = wallet.get_tx_item_fiat(tx_hash=item['txid'], amount_sat=item['amount_sat'], fx=fx, tx_fee=item['fee_sat'])
                item.update(fiat_fields)
        return json_normalize(out)

    @command('wl')
    async def lightning_history(self, wallet: Abstract_Wallet = None):
        """ lightning history. """
        lightning_history = wallet.lnworker.get_lightning_history() if wallet.lnworker else {}
        sorted_hist= sorted(lightning_history.values(), key=lambda x: x.timestamp)
        return json_normalize([x.to_dict() for x in sorted_hist])

    @command('w')
    async def setlabel(self, key, label, wallet: Abstract_Wallet = None):
        """
        Assign a label to an item. Item may be a bitcoin address or a
        transaction ID

        arg:str:key:Key
        arg:str:label:Label
        """
        wallet.set_label(key, label)

    @command('w')
    async def listcontacts(self, wallet: Abstract_Wallet = None):
        """Show your list of contacts"""
        return wallet.contacts

    @command('w')
    async def getopenalias(self, key, wallet: Abstract_Wallet = None):
        """
        Retrieve alias. Lookup in your list of contacts, and for an OpenAlias DNS record.

        arg:str:key:the alias to be retrieved
        """
        d = await wallet.contacts.resolve(key)
        if d.get("type") == "openalias":
            # we always validate DNSSEC now
            d["validated"] = True
        return d

    @command('w')
    async def searchcontacts(self, query, wallet: Abstract_Wallet = None):
        """
        Search through your wallet contacts, return matching entries.

        arg:str:query:Search query
        """
        results = {}
        for key, value in wallet.contacts.items():
            if query.lower() in key.lower():
                results[key] = value
        return results

    @command('w')
    async def listaddresses(self, receiving=False, change=False, labels=False, frozen=False, unused=False, funded=False, balance=False, wallet: Abstract_Wallet = None):
        """List wallet addresses. Returns the list of all addresses in your wallet. Use optional arguments to filter the results.

        arg:bool:receiving:Show only receiving addresses
        arg:bool:change:Show only change addresses
        arg:bool:frozen:Show only frozen addresses
        arg:bool:unused:Show only unused addresses
        arg:bool:funded:Show only funded addresses
        arg:bool:balance:Show the balances of listed addresses
        arg:bool:labels:Show the labels of listed addresses
        """
        out = []
        for addr in wallet.get_addresses():
            if frozen and not wallet.is_frozen_address(addr):
                continue
            if receiving and wallet.is_change(addr):
                continue
            if change and not wallet.is_change(addr):
                continue
            if unused and wallet.adb.is_used(addr):
                continue
            if funded and wallet.adb.is_empty(addr):
                continue
            item = addr
            if labels or balance:
                item = (item,)
            if balance:
                item += (format_satoshis(sum(wallet.get_addr_balance(addr))),)
            if labels:
                item += (repr(wallet.get_label_for_address(addr)),)
            out.append(item)
        return out

    @command('n')
    async def gettransaction(self, txid, wallet: Abstract_Wallet = None):
        """Retrieve a transaction.

        arg:txid:txid:Transaction ID
        """
        tx = None
        if wallet:
            tx = wallet.db.get_transaction(txid)
        if tx is None:
            raw = await self.network.get_transaction(txid)
            if raw:
                tx = Transaction(raw)
            else:
                raise UserFacingException("Unknown transaction")
        if tx.txid() != txid:
            raise UserFacingException("Mismatching txid")
        return tx.serialize()

    @command('')
    async def encrypt(self, pubkey, message) -> str:
        """
        Encrypt a message with a public key. Use quotes if the message contains whitespaces.

        arg:str:pubkey:Public key
        arg:str:message:Clear text message. Use quotes if it contains spaces.
        """
        if not is_hex_str(pubkey):
            raise UserFacingException(f"pubkey must be a hex string instead of {repr(pubkey)}")
        try:
            message = to_bytes(message)
        except TypeError:
            raise UserFacingException(f"message must be a string-like object instead of {repr(message)}")
        public_key = ecc.ECPubkey(bfh(pubkey))
        encrypted = crypto.ecies_encrypt_message(public_key, message)
        return encrypted.decode('utf-8')

    @command('wp')
    async def decrypt(self, pubkey, encrypted, password=None, wallet: Abstract_Wallet = None) -> str:
        """Decrypt a message encrypted with a public key.

        arg:str:encrypted:Encrypted message
        arg:str:pubkey:Public key of one of your wallet addresses
        """
        if not is_hex_str(pubkey):
            raise UserFacingException(f"pubkey must be a hex string instead of {repr(pubkey)}")
        if not isinstance(encrypted, (str, bytes, bytearray)):
            raise UserFacingException(f"encrypted must be a string-like object instead of {repr(encrypted)}")
        decrypted = wallet.decrypt_message(pubkey, encrypted, password)
        return decrypted.decode('utf-8')

    @command('w')
    async def get_request(self, request_id, wallet: Abstract_Wallet = None):
        """Returns a payment request

        arg:str:request_id:The request ID, as seen in list_requests or add_request
        """
        r = wallet.get_request(request_id)
        if not r:
            raise UserFacingException("Request not found")
        return wallet.export_request(r)

    @command('w')
    async def get_invoice(self, invoice_id, wallet: Abstract_Wallet = None):
        """
        Returns an invoice (request for outgoing payment)

        arg:str:invoice_id:The invoice ID, as seen in list_invoices
        """
        r = wallet.get_invoice(invoice_id)
        if not r:
            raise UserFacingException("Request not found")
        return wallet.export_invoice(r)

    def _filter_invoices(self, _list, wallet, pending, expired, paid):
        if pending:
            f = PR_UNPAID
        elif expired:
            f = PR_EXPIRED
        elif paid:
            f = PR_PAID
        else:
            f = None
        if f is not None:
            _list = [x for x in _list if f == wallet.get_invoice_status(x)]
        return _list

    @command('w')
    async def list_requests(self, pending=False, expired=False, paid=False, wallet: Abstract_Wallet = None):
        """
        Returns the list of incoming payment requests saved in the wallet.
        arg:bool:paid:Show only paid requests
        arg:bool:pending:Show only pending requests
        arg:bool:expired:Show only expired requests
        """
        l = wallet.get_sorted_requests()
        l = self._filter_invoices(l, wallet, pending, expired, paid)
        return [wallet.export_request(x) for x in l]

    @command('w')
    async def list_invoices(self, pending=False, expired=False, paid=False, wallet: Abstract_Wallet = None):
        """
        Returns the list of invoices (requests for outgoing payments) saved in the wallet.
        arg:bool:paid:Show only paid invoices
        arg:bool:pending:Show only pending invoices
        arg:bool:expired:Show only expired invoices
        """
        l = wallet.get_invoices()
        l = self._filter_invoices(l, wallet, pending, expired, paid)
        return [wallet.export_invoice(x) for x in l]

    @command('w')
    async def createnewaddress(self, wallet: Abstract_Wallet = None):
        """Create a new receiving address, beyond the gap limit of the wallet"""
        return wallet.create_new_address(False)

    @command('w')
    async def changegaplimit(self, new_limit, iknowwhatimdoing=False, wallet: Abstract_Wallet = None):
        """
        Change the gap limit of the wallet.

        arg:int:new_limit:new gap limit
        arg:bool:iknowwhatimdoing:Acknowledge that I understand the full implications of what I am about to do
        """
        if not iknowwhatimdoing:
            raise UserFacingException(
                "WARNING: Are you SURE you want to change the gap limit?\n"
                "It makes recovering your wallet from seed difficult!\n"
                "Please do your research and make sure you understand the implications.\n"
                "Typically only merchants and power users might want to do this.\n"
                "To proceed, try again, with the --iknowwhatimdoing option.")
        if not isinstance(wallet, Deterministic_Wallet):
            raise UserFacingException("This wallet is not deterministic.")
        return wallet.change_gap_limit(new_limit)

    @command('wn')
    async def getminacceptablegap(self, wallet: Abstract_Wallet = None):
        """Returns the minimum value for gap limit that would be sufficient to discover all
        known addresses in the wallet.
        """
        if not isinstance(wallet, Deterministic_Wallet):
            raise UserFacingException("This wallet is not deterministic.")
        if not wallet.is_up_to_date():
            raise NotSynchronizedException("Wallet not fully synchronized.")
        return wallet.min_acceptable_gap()

    @command('w')
    async def getunusedaddress(self, wallet: Abstract_Wallet = None):
        """Returns the first unused address of the wallet, or None if all addresses are used.
        An address is considered as used if it has received a transaction, or if it is used in a payment request."""
        return wallet.get_unused_address()

    @command('w')
    async def add_request(self, amount, memo='', expiry=3600, lightning=False, force=False, wallet: Abstract_Wallet = None):
        """Create a payment request, using the first unused address of the wallet.

        The address will be considered as used after this operation.
        If no payment is received, the address will be considered as unused if the payment request is deleted from the wallet.

        arg:decimal:amount:Requested amount (in btc)
        arg:str:memo:Description of the request
        arg:bool:force:Create new address beyond gap limit, if no more addresses are available.
        arg:bool:lightning:Create lightning request.
        arg:int:expiry:Time in seconds.
        """
        amount = satoshis(amount)
        if not lightning:
            addr = wallet.get_unused_address()
            if addr is None:
                if force:
                    addr = wallet.create_new_address(False)
                else:
                    return False
        else:
            addr = None
        expiry = int(expiry) if expiry else None
        key = wallet.create_request(amount, memo, expiry, addr)
        req = wallet.get_request(key)
        return wallet.export_request(req)

    @command('wnl')
    async def add_hold_invoice(
            self,
            payment_hash: str,
            amount: Optional[Decimal] = None,
            memo: str = "",
            expiry: int = 3600,
            min_final_cltv_expiry_delta: int = MIN_FINAL_CLTV_DELTA_ACCEPTED * 2,
            wallet: Abstract_Wallet = None
    ) -> dict:
        """
        Create a lightning hold invoice for the given payment hash. Hold invoices have to get settled manually later.
        HTLCs will get failed automatically if block_height + 144 > htlc.cltv_abs, if the intention is to
        settle them as late as possible a safety margin of some blocks should be used to prevent them
        from getting failed accidentally.

        arg:str:payment_hash:Hex encoded payment hash to be used for the invoice
        arg:decimal:amount:Optional requested amount (in btc)
        arg:str:memo:Optional description of the invoice
        arg:int:expiry:Optional expiry in seconds (default: 3600s)
        arg:int:min_final_cltv_expiry_delta:Optional min final cltv expiry delta (default: 294 blocks)
        """
        assert len(payment_hash) == 64, f"Invalid payment hash length: {len(payment_hash)} != 64"
        assert not wallet.lnworker.get_payment_info(bfh(payment_hash), direction=RECEIVED), "Payment hash already used!"
        assert payment_hash not in wallet.lnworker.dont_expire_htlcs, "Payment hash already used!"
        assert wallet.lnworker.get_preimage(bfh(payment_hash)) is None, "Already got a preimage for this payment hash!"
        assert MIN_FINAL_CLTV_DELTA_ACCEPTED < min_final_cltv_expiry_delta < 576, "Use a sane min_final_cltv_expiry_delta value"
        amount = amount if amount and satoshis(amount) > 0 else None  # make amount either >0 or None
        inbound_capacity = wallet.lnworker.num_sats_can_receive()
        assert inbound_capacity > satoshis(amount or 0), \
            f"Not enough inbound capacity [{inbound_capacity} sat] to receive this payment"

        wallet.lnworker.add_payment_info_for_hold_invoice(
            bfh(payment_hash),
            lightning_amount_sat=satoshis(amount) if amount else None,
            min_final_cltv_delta=min_final_cltv_expiry_delta,
            exp_delay=expiry,
        )
        info = wallet.lnworker.get_payment_info(bfh(payment_hash), direction=RECEIVED)
        lnaddr, invoice = wallet.lnworker.get_bolt11_invoice(
            payment_info=info,
            message=memo,
            fallback_address=None
        )
        # this prevents incoming htlcs from getting expired while the preimage isn't set.
        # If their blocks to expiry fall below MIN_FINAL_CLTV_DELTA_ACCEPTED they will get failed.
        wallet.lnworker.dont_expire_htlcs[payment_hash] = MIN_FINAL_CLTV_DELTA_ACCEPTED
        wallet.set_label(payment_hash, memo)
        result = {
            "invoice": invoice
        }
        return result

    @command('wnl')
    async def settle_hold_invoice(self, preimage: str, wallet: Abstract_Wallet = None) -> dict:
        """
        Settles lightning hold invoice with the given preimage.
        Doesn't block until actual settlement of the HTLCs.

        arg:str:preimage:Hex encoded preimage of the invoice to be settled
        """
        assert len(preimage) == 64, f"Invalid payment_hash length: {len(preimage)} != 64"
        payment_hash: str = crypto.sha256(bfh(preimage)).hex()
        assert payment_hash not in wallet.lnworker._preimages, f"Invoice {payment_hash=} already settled"
        info = wallet.lnworker.get_payment_info(bfh(payment_hash), direction=RECEIVED)
        assert info, f"Couldn't find lightning invoice for {payment_hash=}"
        assert payment_hash in wallet.lnworker.dont_expire_htlcs, f"Invoice {payment_hash=} not a hold invoice?"
        assert wallet.lnworker.is_complete_mpp(bfh(payment_hash)), \
            f"MPP incomplete, cannot settle hold invoice {payment_hash} yet"
        assert (wallet.lnworker.get_payment_mpp_amount_msat(bfh(payment_hash)) or 0) >= (info.amount_msat or 0)
        wallet.lnworker.save_preimage(bfh(payment_hash), bfh(preimage))
        util.trigger_callback('wallet_updated', wallet)
        result = {
            "settled": payment_hash
        }
        return result

    @command('wnl')
    async def cancel_hold_invoice(self, payment_hash: str, wallet: Abstract_Wallet = None) -> dict:
        """
        Cancels lightning hold invoice 'payment_hash'.

        arg:str:payment_hash:Payment hash in hex of the hold invoice
        """
        assert wallet.lnworker.get_payment_info(bfh(payment_hash), direction=RECEIVED), \
            f"Couldn't find lightning invoice for payment hash {payment_hash}"
        assert payment_hash not in wallet.lnworker._preimages, "Cannot cancel anymore, preimage already given."
        assert payment_hash in wallet.lnworker.dont_expire_htlcs, f"{payment_hash=} not a hold invoice?"
        # set to PR_UNPAID so it can get deleted
        wallet.lnworker.set_payment_status(bfh(payment_hash), PR_UNPAID, direction=RECEIVED)
        wallet.lnworker.delete_payment_info(payment_hash, direction=RECEIVED)
        wallet.set_label(payment_hash, None)
        del wallet.lnworker.dont_expire_htlcs[payment_hash]
        while wallet.lnworker.is_complete_mpp(bfh(payment_hash)):
            # block until the htlcs got failed
            await asyncio.sleep(0.1)
        result = {
            "cancelled": payment_hash
        }
        return result

    @command('wnl')
    async def check_hold_invoice(self, payment_hash: str, wallet: Abstract_Wallet = None) -> dict:
        """
        Checks the status of a lightning hold invoice 'payment_hash'.
        Returns: {
            "status": unpaid | paid | settled | unknown (cancelled or not found),
            "received_amount_sat": currently received amount (pending htlcs or final after settling),
            "invoice_amount_sat": Invoice amount, Optional (only if invoice is found),
            "closest_htlc_expiry_height": Closest absolute expiry height of all received htlcs
            (Note: HTLCs will get failed automatically if block_height + 144 > htlc_expiry_height)
        }

        arg:str:payment_hash:Payment hash in hex of the hold invoice
        """
        assert len(payment_hash) == 64, f"Invalid payment_hash length: {len(payment_hash)} != 64"
        info: Optional['PaymentInfo'] = wallet.lnworker.get_payment_info(bfh(payment_hash), direction=RECEIVED)
        is_complete_mpp: bool = wallet.lnworker.is_complete_mpp(bfh(payment_hash))
        amount_sat = (wallet.lnworker.get_payment_mpp_amount_msat(bfh(payment_hash)) or 0) // 1000
        result = {
            "status": "unknown",
            "received_amount_sat": amount_sat,
        }
        if info is None:
            pass
        elif not is_complete_mpp and not wallet.lnworker.get_preimage_hex(payment_hash):
            # is_complete_mpp is False for settled payments
            result["status"] = "unpaid"
        elif is_complete_mpp and payment_hash in wallet.lnworker.dont_expire_htlcs:
            result["status"] = "paid"
            payment_key: str = wallet.lnworker._get_payment_key(bfh(payment_hash)).hex()
            htlc_status = wallet.lnworker.received_mpp_htlcs[payment_key]
            result["closest_htlc_expiry_height"] = min(
                mpp_htlc.htlc.cltv_abs for mpp_htlc in htlc_status.htlcs
            )
        elif wallet.lnworker.get_preimage_hex(payment_hash) is not None:
            result["status"] = "settled"
            plist = wallet.lnworker.get_payments(status='settled')[bfh(payment_hash)]
            _dir, amount_msat, _fee, _ts = wallet.lnworker.get_payment_value(None, plist)
            result["received_amount_sat"] = amount_msat // 1000
            result['preimage'] = wallet.lnworker.get_preimage_hex(payment_hash)
        if info is not None:
            result["invoice_amount_sat"] = (info.amount_msat or 0) // 1000
        return result

    @command('wl')
    async def export_lightning_preimage(self, payment_hash: str, wallet: 'Abstract_Wallet' = None) -> Optional[str]:
        """
        Returns the stored preimage of the given payment_hash if it is known.

        arg:str:payment_hash: Hash of the preimage
        """
        preimage = wallet.lnworker.get_preimage_hex(payment_hash)
        assert preimage is None or crypto.sha256(bytes.fromhex(preimage)).hex() == payment_hash
        return preimage

    @command('w')
    async def addtransaction(self, tx, wallet: Abstract_Wallet = None):
        """
        Add a transaction to the wallet history, without broadcasting it.

        arg:tx:tx:Transaction, in hexadecimal format.
        """
        tx = Transaction(tx)
        if not wallet.adb.add_transaction(tx):
            return False
        wallet.save_db()
        return tx.txid()

    @command('w')
    async def delete_request(self, request_id, wallet: Abstract_Wallet = None):
        """Remove an incoming payment request

        arg:str:request_id:The request ID, as returned in list_invoices
        """
        return wallet.delete_request(request_id)

    @command('w')
    async def delete_invoice(self, invoice_id, wallet: Abstract_Wallet = None):
        """Remove an outgoing payment invoice

        arg:str:invoice_id:The invoice ID, as returned in list_invoices
        """
        return wallet.delete_invoice(invoice_id)

    @command('w')
    async def clear_requests(self, wallet: Abstract_Wallet = None):
        """Remove all payment requests"""
        wallet.clear_requests()
        return True

    @command('w')
    async def clear_invoices(self, wallet: Abstract_Wallet = None):
        """Remove all invoices"""
        wallet.clear_invoices()
        return True

    @command('n')
    async def notify(self, address: str, URL: Optional[str]):
        """
        Watch an address. Every time the address changes, a http POST is sent to the URL.
        Call with an empty URL to stop watching an address.

        arg:str:address:Bitcoin address
        arg:str:URL:The callback URL
        """
        if not hasattr(self, "_notifier"):
            self._notifier = Notifier(self.network)
        if URL:
            await self._notifier.start_watching_addr(address, URL)
        else:
            await self._notifier.stop_watching_addr(address)
        return True

    @command('wn')
    async def is_synchronized(self, wallet: Abstract_Wallet = None):
        """ return wallet synchronization status """
        return wallet.is_up_to_date()

    @command('wn')
    async def wait_for_sync(self, wallet: Abstract_Wallet = None):
        """Block until the wallet synchronization finishes."""
        while True:
            if wallet.is_up_to_date():
                return True
            await wallet.up_to_date_changed_event.wait()

    @command('n')
    async def getfeerate(self):
        """
        Return current fee estimate given network conditions (in sat/kvByte).
        To change the fee policy, use 'getconfig/setconfig fee_policy'
        """
        fee_policy = FeePolicy(self.config.FEE_POLICY)
        description = fee_policy.get_target_text()
        feerate = fee_policy.fee_per_kb(self.network)
        tooltip = fee_policy.get_estimate_text(self.network)
        return {
            'policy': fee_policy.get_descriptor(),
            'description': description,
            'sat/kvB': feerate,
            'tooltip': tooltip,
        }

    @command('n')
    async def test_inject_fee_etas(self, fee_est):
        """
        Inject fee estimates into the network object, as if they were coming from connected servers.
        `setconfig 'test_disable_automatic_fee_eta_update' true` to prevent Network from overriding
        the configured fees.
        Useful on regtest.

        arg:str:fee_est:dict of ETA-based fee estimates, encoded as str
        """
        if not isinstance(fee_est, dict):
            fee_est = ast.literal_eval(fee_est)
        assert isinstance(fee_est, dict), f"unexpected type for fee_est. got {repr(fee_est)}"
        # populate missing high-block-number estimates using default relay fee.
        # e.g. {"25": 2222} -> {"25": 2222, "144": 1000, "1008": 1000}
        furthest_estimate = max(fee_est.keys()) if fee_est else 0
        further_fee_est = {
            eta_target: FEERATE_DEFAULT_RELAY for eta_target in FEE_ETA_TARGETS
            if eta_target > furthest_estimate
        }
        fee_est.update(further_fee_est)
        self.network.update_fee_estimates(fee_est=fee_est)

    @command('w')
    async def removelocaltx(self, txid, wallet: Abstract_Wallet = None):
        """Remove a 'local' transaction from the wallet, and its dependent
        transactions.

        arg:txid:txid:Transaction ID
        """
        height = wallet.adb.get_tx_height(txid).height()
        if height != TX_HEIGHT_LOCAL:
            raise UserFacingException(
                f'Only local transactions can be removed. '
                f'This tx has height: {height} != {TX_HEIGHT_LOCAL}')
        wallet.adb.remove_transaction(txid)
        wallet.save_db()

    @command('wn')
    async def get_tx_status(self, txid, wallet: Abstract_Wallet = None):
        """Returns some information regarding the tx. For now, only confirmations.
        The transaction must be related to the wallet.

        arg:txid:txid:Transaction ID
        """
        if not wallet.db.get_transaction(txid):
            raise UserFacingException("Transaction not in wallet.")
        return {
            "confirmations": wallet.adb.get_tx_height(txid).conf,
        }

    @command('')
    async def help(self):
        """Show help about a command"""
        # for the python console
        return sorted(known_commands.keys())

    # lightning network commands
    @command('wnl')
    async def add_peer(self, connection_string, timeout=20, gossip=False, wallet: Abstract_Wallet = None):
        """
        Connect to a lightning node

        arg:str:connection_string:Lightning network node ID or network address
        arg:bool:gossip:Apply command to your gossip node instead of wallet node
        arg:int:timeout:Timeout in seconds (default=20)
        """
        lnworker = self.network.lngossip if gossip else wallet.lnworker
        peer = await lnworker.lnpeermgr.add_peer(connection_string)
        try:
            await util.wait_for2(peer.initialized, timeout=LN_P2P_NETWORK_TIMEOUT)
        except (CancelledError, Exception) as e:
            #  FIXME often simply CancelledError and real cause (e.g. timeout) remains hidden
            raise UserFacingException(f"Connection failed: {repr(e)}")
        return True

    @command('wnl')
    async def gossip_info(self, wallet: Abstract_Wallet = None):
        """Display statistics about lightninig gossip"""
        lngossip = self.network.lngossip
        channel_db = lngossip.channel_db
        forwarded = dict([(key.hex(), p._num_gossip_messages_forwarded) for key, p in wallet.lnworker.lnpeermgr.peers.items()]),
        out = {
            'received': {
                'channel_announcements': lngossip._num_chan_ann,
                'channel_updates': lngossip._num_chan_upd,
                'channel_updates_good': lngossip._num_chan_upd_good,
                'node_announcements': lngossip._num_node_ann,
            },
            'database': {
                'nodes': channel_db.num_nodes,
                'channels': channel_db.num_channels,
                'channel_policies': channel_db.num_policies,
            },
            'forwarded': forwarded,
        }
        return out

    @command('wnl')
    async def list_peers(self, gossip=False, wallet: Abstract_Wallet = None):
        """
        List lightning peers of your node

        arg:bool:gossip:Apply command to your gossip node instead of wallet node
        """
        lnworker = self.network.lngossip if gossip else wallet.lnworker
        return [{
            'node_id': p.pubkey.hex(),
            'address': p.transport.name(),
            'initialized': p.is_initialized(),
            'features': str(LnFeatures(p.features)),
            'channels': [c.funding_outpoint.to_str() for c in p.channels.values()],
        } for p in lnworker.lnpeermgr.peers.values()]

    @command('wpnl')
    async def open_channel(self, connection_string, amount, push_amount=0, public=False, zeroconf=False, password=None, wallet: Abstract_Wallet = None):
        """
        Open a lightning channel with a peer

        arg:str:connection_string:Lightning network node ID or network address
        arg:decimal_or_max:amount:funding amount (in BTC)
        arg:decimal:push_amount:Push initial amount (in BTC)
        arg:bool:public:The channel will be announced
        arg:bool:zeroconf:request zeroconf channel
        """
        if not wallet.can_have_lightning():
            raise UserFacingException("This wallet cannot create new channels")
        funding_sat = satoshis(amount)
        push_sat = satoshis(push_amount)
        peer = await wallet.lnworker.lnpeermgr.add_peer(connection_string)
        chan, funding_tx = await wallet.lnworker.open_channel_with_peer(
            peer, funding_sat,
            push_sat=push_sat,
            public=public,
            zeroconf=zeroconf,
            password=password)
        return chan.funding_outpoint.to_str()

    @command('')
    async def decode_invoice(self, invoice: str):
        """
        Decode a lightning invoice

        arg:str:invoice:Lightning invoice (bolt 11)
        """
        invoice = Invoice.from_bech32(invoice)
        return invoice.to_debug_json()

    @command('wnpl')
    async def lnpay(
        self,
        invoice: str,
        timeout: int = 120,
        max_cltv: Optional[int] = None,
        max_fee_msat: Optional[int] = None,
        password=None,
        wallet: Abstract_Wallet = None
    ):
        """
        Pay a lightning invoice
        Note: it is *not* safe to try paying the same invoice multiple times with a timeout.
              It is only safe to retry paying the same invoice if there are no more pending HTLCs
              with the same payment_hash.  # FIXME should there even be a default timeout? just block forever.

        arg:str:invoice:Lightning invoice (bolt 11)
        arg:int:timeout:Timeout in seconds (default=120)
        arg:int:max_cltv:Maximum total time lock for the route (default=4032+invoice_final_cltv_delta)
        arg:int:max_fee_msat:Maximum absolute fee budget for the payment (if unset, the default is a percentage fee based on config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS)
        """
        # note: The "timeout" param works via black magic.
        #       The CLI-parser stores it in the config, and the argname matches config.cv.CLI_TIMEOUT.key().
        #       - it works when calling the CLI and there is also a daemon (online command)
        #       - FIXME it does NOT work when calling an offline command (-o)
        #       - FIXME it does NOT work when calling RPC directly (e.g. curl)
        lnworker = wallet.lnworker
        lnaddr = lnworker._check_bolt11_invoice(invoice)  # also checks if amount is given
        payment_hash = lnaddr.paymenthash
        invoice_obj = Invoice.from_bech32(invoice)
        assert not max_fee_msat or max_fee_msat < max(invoice_obj.amount_msat // 2, 1_000_000), \
                                    f"{max_fee_msat=} > max(invoice amount msat / 2, 1_000_000)"
        wallet.save_invoice(invoice_obj)
        if max_cltv is not None:
            # The cltv budget excludes the final cltv delta which is why it is deducted here
            # so the whole used cltv is <= max_cltv
            assert max_cltv <= NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE, \
                    f"{max_cltv=} > {NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE=}"
            max_cltv_remaining = max_cltv - lnaddr.get_min_final_cltv_delta()
            assert max_cltv_remaining > 0, f"{max_cltv=} - {lnaddr.get_min_final_cltv_delta()=} < 1"
            max_cltv = max_cltv_remaining
        budget = PaymentFeeBudget.from_invoice_amount(
            config=wallet.config,
            invoice_amount_msat=invoice_obj.amount_msat,
            max_cltv_delta=max_cltv,
            max_fee_msat=max_fee_msat,
        )
        success, log = await lnworker.pay_invoice(invoice_obj, budget=budget)
        return {
            'payment_hash': payment_hash.hex(),
            'success': success,
            'preimage': lnworker.get_preimage(payment_hash).hex() if success else None,
            'log': [x.formatted_tuple() for x in log]
        }

    @command('wl')
    async def nodeid(self, wallet: Abstract_Wallet = None):
        """Return the Lightning Node ID of a wallet"""
        listen_addr = self.config.LIGHTNING_LISTEN
        return wallet.lnworker.node_keypair.pubkey.hex() + (('@' + listen_addr) if listen_addr else '')

    @command('wl')
    async def list_channels(self, wallet: Abstract_Wallet = None):
        """Return the list of Lightning channels in a wallet"""
        # FIXME: we need to be online to display capacity of backups
        from .lnutil import LOCAL, REMOTE, format_short_channel_id
        channels = list(wallet.lnworker.channels.items())
        backups = list(wallet.lnworker.channel_backups.items())
        return [
            {
                'type': 'CHANNEL',
                'short_channel_id': format_short_channel_id(chan.short_channel_id) if chan.short_channel_id else None,
                'channel_id': chan.channel_id.hex(),
                'channel_point': chan.funding_outpoint.to_str(),
                'closing_txid': chan.get_closing_height()[0] if chan.get_closing_height() else None,
                'state': chan.get_state().name,
                'peer_state': chan.peer_state.name,
                'remote_pubkey': chan.node_id.hex(),
                'local_balance': chan.balance(LOCAL)//1000,
                'remote_balance': chan.balance(REMOTE)//1000,
                'local_ctn': chan.get_latest_ctn(LOCAL),
                'remote_ctn': chan.get_latest_ctn(REMOTE),
                'local_reserve': chan.config[REMOTE].reserve_sat,  # their config has our reserve
                'remote_reserve': chan.config[LOCAL].reserve_sat,
                'local_unsettled_sent': chan.balance_tied_up_in_htlcs_by_direction(LOCAL, direction=SENT) // 1000,
                'remote_unsettled_sent': chan.balance_tied_up_in_htlcs_by_direction(REMOTE, direction=SENT) // 1000,
            } for channel_id, chan in channels
        ] + [
            {
                'type': 'BACKUP',
                'short_channel_id': format_short_channel_id(chan.short_channel_id) if chan.short_channel_id else None,
                'channel_id': chan.channel_id.hex(),
                'channel_point': chan.funding_outpoint.to_str(),
                'closing_txid': chan.get_closing_height()[0] if chan.get_closing_height() else None,
                'state': chan.get_state().name,
            } for channel_id, chan in backups
        ]

    @command('wnl')
    async def enable_htlc_settle(self, b: bool, wallet: Abstract_Wallet = None):
        """
        command used in regtests

        arg:bool:b:boolean
        """
        wallet.lnworker.enable_htlc_settle = b

    @command('n')
    async def clear_ln_blacklist(self):
        if self.network.path_finder:
            self.network.path_finder.clear_blacklist()

    @command('n')
    async def reset_liquidity_hints(self):
        if self.network.path_finder:
            self.network.path_finder.liquidity_hints.reset_liquidity_hints()
            self.network.path_finder.clear_blacklist()

    @command('wnpl')
    async def close_channel(self, channel_point, force=False, password=None, wallet: Abstract_Wallet = None):
        """
        Close a lightning channel.
        Returns txid of closing tx.

        arg:str:channel_point:channel point
        arg:bool:force:Force closes (broadcast local commitment transaction)
        """
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        if chan_id not in wallet.lnworker.channels:
            raise UserFacingException(f'Unknown channel {channel_point}')
        coro = wallet.lnworker.force_close_channel(chan_id) if force else wallet.lnworker.close_channel(chan_id)
        return await coro

    @command('wnpl')
    async def request_force_close(self, channel_point, connection_string=None, password=None, wallet: Abstract_Wallet = None):
        """
        Requests the remote to force close a channel.
        If a connection string is passed, can be used without having state or any backup for the channel.
        Assumes that channel was originally opened with the same local peer (node_keypair).

        arg:str:connection_string:Lightning network node ID or network address
        arg:str:channel_point:channel point
        """
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        if chan_id not in wallet.lnworker.channels and chan_id not in wallet.lnworker.channel_backups:
            raise UserFacingException(f'Unknown channel {channel_point}')
        await wallet.lnworker.request_force_close(chan_id, connect_str=connection_string)

    @command('wpl')
    async def export_channel_backup(self, channel_point, password=None, wallet: Abstract_Wallet = None):
        """
        Returns an encrypted channel backup

        arg:str:channel_point:Channel outpoint
        """
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        if chan_id not in wallet.lnworker.channels:
            raise UserFacingException(f'Unknown channel {channel_point}')
        return wallet.lnworker.export_channel_backup(chan_id)

    @command('wl')
    async def import_channel_backup(self, encrypted, wallet: Abstract_Wallet = None):
        """
        arg:str:encrypted:Encrypted channel backup
        """
        return wallet.lnworker.import_channel_backup(encrypted)

    @command('wnpl')
    async def get_channel_ctx(self, channel_point, password=None, iknowwhatimdoing=False, wallet: Abstract_Wallet = None):
        """
        return the current commitment transaction of a channel

        arg:str:channel_point:Channel outpoint
        arg:bool:iknowwhatimdoing:Acknowledge that I understand the full implications of what I am about to do
        """
        if not iknowwhatimdoing:
            raise UserFacingException(
                "WARNING: this command is potentially unsafe.\n"
                "To proceed, try again, with the --iknowwhatimdoing option.")
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        if chan_id not in wallet.lnworker.channels:
            raise UserFacingException(f'Unknown channel {channel_point}')
        chan = wallet.lnworker.channels[chan_id]
        tx = chan.force_close_tx()
        return tx.serialize()

    @command('wnl')
    async def get_watchtower_ctn(self, channel_point, wallet: Abstract_Wallet = None):
        """
        Return the local watchtower's ctn of channel. used in regtests

        arg:str:channel_point:Channel outpoint (txid:index)
        """
        return wallet.lnworker.get_watchtower_ctn(channel_point)

    @command('wnpl')
    async def rebalance_channels(self, from_scid, dest_scid, amount, password=None, wallet: Abstract_Wallet = None):
        """
        Rebalance channels.
        If trampoline is used, channels must be with different trampolines.

        arg:str:from_scid:Short channel ID
        arg:str:dest_scid:Short channel ID
        arg:decimal:amount:Amount (in BTC)

        """
        from .lnutil import ShortChannelID
        from_scid = ShortChannelID.from_str(from_scid)
        dest_scid = ShortChannelID.from_str(dest_scid)
        from_channel = wallet.lnworker.get_channel_by_short_id(from_scid)
        dest_channel = wallet.lnworker.get_channel_by_short_id(dest_scid)
        amount_sat = satoshis(amount)
        success, log = await wallet.lnworker.rebalance_channels(
            from_channel,
            dest_channel,
            amount_msat=amount_sat * 1000,
        )
        return {
            'success': success,
            'log': [x.formatted_tuple() for x in log]
        }

    @command('wnl')
    async def get_submarine_swap_providers(self, query_time=15, wallet: Abstract_Wallet = None):
        """
        Queries nostr relays for available submarine swap providers.

        To configure one of the providers use:
        setconfig swapserver_npub 'npub...'

        arg:int:query_time:Optional timeout how long the relays should be queried for provider announcements. Default: 15 sec
        """
        sm = wallet.lnworker.swap_manager
        async with sm.create_transport() as transport:
            assert isinstance(transport, NostrTransport)
            await asyncio.sleep(query_time)
            offers = transport.get_recent_offers()
        result = {}
        for offer in offers:
            result[offer.server_npub] = {
                "percentage_fee": offer.pairs.percentage,
                "max_forward_sat": offer.pairs.max_forward,
                "max_reverse_sat": offer.pairs.max_reverse,
                "min_amount_sat": offer.pairs.min_amount,
                "prepayment": 2 * offer.pairs.mining_fee,
            }
        return result

    @command('wnpl')
    async def normal_swap(self, onchain_amount, lightning_amount, password=None, wallet: Abstract_Wallet = None):
        """
        Normal submarine swap: send on-chain BTC, receive on Lightning

        arg:decimal_or_dryrun:lightning_amount:Amount to be received, in BTC. Set it to 'dryrun' to receive a value
        arg:decimal_or_dryrun:onchain_amount:Amount to be sent, in BTC. Set it to 'dryrun' to receive a value
        """
        sm = wallet.lnworker.swap_manager
        assert self.config.SWAPSERVER_NPUB or self.config.SWAPSERVER_URL, \
            "Configure swap provider first. See 'get_submarine_swap_providers'."
        async with sm.create_transport() as transport:
            try:
                await asyncio.wait_for(sm.is_initialized.wait(), timeout=15)
            except asyncio.TimeoutError:
                raise TimeoutError("Could not find configured swap provider. Setup another one. See 'get_submarine_swap_providers'")
            if lightning_amount == 'dryrun':
                onchain_amount_sat = satoshis(onchain_amount)
                lightning_amount_sat = sm.get_recv_amount(onchain_amount_sat, is_reverse=False)
                txid = None
            elif onchain_amount == 'dryrun':
                lightning_amount_sat = satoshis(lightning_amount)
                onchain_amount_sat = sm.get_send_amount(lightning_amount_sat, is_reverse=False)
                txid = None
            else:
                lightning_amount_sat = satoshis(lightning_amount)
                onchain_amount_sat = satoshis(onchain_amount)
                txid = await wallet.lnworker.swap_manager.normal_swap(
                    transport=transport,
                    lightning_amount_sat=lightning_amount_sat,
                    expected_onchain_amount_sat=onchain_amount_sat,
                    password=password,
                )

        return {
            'txid': txid,
            'lightning_amount': format_satoshis(lightning_amount_sat),
            'onchain_amount': format_satoshis(onchain_amount_sat),
        }

    @command('wnpl')
    async def reverse_swap(
        self, lightning_amount, onchain_amount, prepayment='dryrun', password=None, wallet: Abstract_Wallet = None,
    ):
        """
        Reverse submarine swap: send on Lightning, receive on-chain

        arg:decimal_or_dryrun:lightning_amount:Amount to be sent, in BTC. Set it to 'dryrun' to receive a value
        arg:decimal_or_dryrun:onchain_amount:Amount to be received, in BTC. Set it to 'dryrun' to receive a value
        arg:decimal_or_dryrun:prepayment:Lightning payment required by the swap provider in order to cover their mining fees. This is included in lightning_amount. However, this part of the operation is not trustless; the provider is trusted to fail this payment if the swap fails.
        """
        sm = wallet.lnworker.swap_manager
        assert self.config.SWAPSERVER_NPUB or self.config.SWAPSERVER_URL, \
            "Configure swap provider first. See 'get_submarine_swap_providers'."
        async with sm.create_transport() as transport:
            try:
                await asyncio.wait_for(sm.is_initialized.wait(), timeout=15)
            except asyncio.TimeoutError:
                raise TimeoutError("Could not find configured swap provider. Setup another one. See 'get_submarine_swap_providers'")
            if onchain_amount == 'dryrun':
                lightning_amount_sat = satoshis(lightning_amount)
                onchain_amount_sat = sm.get_recv_amount(lightning_amount_sat, is_reverse=True)
                assert prepayment == "dryrun", f"Cannot use {prepayment=} in dryrun. Set it to 'dryrun'."
                prepayment_sat = 2 * sm.mining_fee
                funding_txid = None
            elif lightning_amount == 'dryrun':
                onchain_amount_sat = satoshis(onchain_amount)
                lightning_amount_sat = sm.get_send_amount(onchain_amount_sat, is_reverse=True)
                assert prepayment == "dryrun", f"Cannot use {prepayment=} in dryrun. Set it to 'dryrun'."
                prepayment_sat = 2 * sm.mining_fee
                funding_txid = None
            else:
                lightning_amount_sat = satoshis(lightning_amount)
                claim_fee = sm.get_fee_for_txbatcher()
                onchain_amount_sat = satoshis(onchain_amount) + claim_fee
                assert prepayment != "dryrun", "Provide the 'prepayment' obtained from the dryrun."
                prepayment_sat = satoshis(prepayment)
                funding_txid = await wallet.lnworker.swap_manager.reverse_swap(
                    transport=transport,
                    lightning_amount_sat=lightning_amount_sat,
                    expected_onchain_amount_sat=onchain_amount_sat,
                    prepayment_sat=prepayment_sat,
                )
        return {
            'funding_txid': funding_txid,
            'lightning_amount': format_satoshis(lightning_amount_sat),
            'onchain_amount': format_satoshis(onchain_amount_sat),
            'prepayment': format_satoshis(prepayment_sat)
        }

    @command('n')
    async def convert_currency(self, from_amount=1, from_ccy='', to_ccy=''):
        """
        Converts the given amount of currency to another using the
        configured exchange rate source.

        arg:decimal:from_amount:Amount to convert (default=1)
        arg:str:from_ccy:Currency to convert from
        arg:str:to_ccy:Currency to convert to
        """
        if not self.daemon.fx.is_enabled():
            raise UserFacingException("FX is disabled. To enable, run: 'electrum setconfig use_exchange_rate true'")
        # Currency codes are uppercase
        from_ccy = from_ccy.upper()
        to_ccy = to_ccy.upper()
        # Default currencies
        if from_ccy == '':
            from_ccy = "BTC" if to_ccy != "BTC" else self.daemon.fx.ccy
        if to_ccy == '':
            to_ccy = "BTC" if from_ccy != "BTC" else self.daemon.fx.ccy
        # Get current rates
        rate_from = self.daemon.fx.exchange.get_cached_spot_quote(from_ccy)
        rate_to = self.daemon.fx.exchange.get_cached_spot_quote(to_ccy)
        # Test if currencies exist
        if rate_from.is_nan():
            raise UserFacingException(f'Currency to convert from ({from_ccy}) is unknown or rate is unavailable')
        if rate_to.is_nan():
            raise UserFacingException(f'Currency to convert to ({to_ccy}) is unknown or rate is unavailable')
        # Conversion
        try:
            from_amount = to_decimal(from_amount)
            to_amount = from_amount / rate_from * rate_to
        except InvalidOperation:
            raise Exception("from_amount is not a number")
        return {
            "from_amount": self.daemon.fx.ccy_amount_str(from_amount, add_thousands_sep=False, ccy=from_ccy),
            "to_amount": self.daemon.fx.ccy_amount_str(to_amount, add_thousands_sep=False, ccy=to_ccy),
            "from_ccy": from_ccy,
            "to_ccy": to_ccy,
            "source": self.daemon.fx.exchange.name(),
        }

    @command('wnl')
    async def send_onion_message(self, node_id_or_blinded_path_hex: str, message: str, wallet: Abstract_Wallet = None):
        """
        Send an onion message with onionmsg_tlv.message payload to node_id.

        arg:str:node_id_or_blinded_path_hex:node id or blinded path
        arg:str:message:Message to send
        """
        assert wallet
        assert wallet.lnworker
        assert node_id_or_blinded_path_hex
        assert message

        node_id_or_blinded_path = bfh(node_id_or_blinded_path_hex)
        assert len(node_id_or_blinded_path) >= 33

        destination_payload = {
            'message': {'text': message.encode('utf-8')}
        }

        try:
            send_onion_message_to(wallet.lnworker, node_id_or_blinded_path, destination_payload)
            return {'success': True}
        except Exception as e:
            msg = str(e)

        return {
            'success': False,
            'msg': msg
        }

    @command('wnl')
    async def get_blinded_path_via(self, node_id: str, dummy_hops: int = 0, wallet: Abstract_Wallet = None):
        """
        Create a blinded path with node_id as introduction point. Introduction point must be direct peer of me.

        arg:str:node_id:Node pubkey in hex format
        arg:int:dummy_hops:Number of dummy hops to add
        """
        # TODO: allow introduction_point to not be a direct peer and construct a route
        assert wallet
        assert node_id

        pubkey = bfh(node_id)
        assert len(pubkey) == 33, 'invalid node_id'

        peer = wallet.lnworker.lnpeermgr.peers[pubkey]
        assert peer, 'node_id not a peer'

        path = [pubkey, wallet.lnworker.node_keypair.pubkey]
        session_key = os.urandom(32)
        blinded_path = create_blinded_path(session_key, path=path, final_recipient_data={}, dummy_hops=dummy_hops)

        with io.BytesIO() as blinded_path_fd:
            OnionWireSerializer.write_field(
                fd=blinded_path_fd,
                field_type='blinded_path',
                count=1,
                value=blinded_path)
            encoded_blinded_path = blinded_path_fd.getvalue()

        return encoded_blinded_path.hex()


def plugin_command(s, plugin_name):
    """Decorator to register a cli command inside a plugin. To be used within a commands.py file
    in the plugins root."""
    # atm all plugin commands require a daemon, cannot be run in 'offline' mode:
    if 'n' not in s:
        s += 'n'
    def decorator(func):
        assert len(plugin_name) > 0, "Plugin name must not be empty"
        func.plugin_name = plugin_name
        name = plugin_name + '_' + func.__name__
        if name in known_commands or hasattr(Commands, name):
            raise Exception(f"Command name {name} already exists. Plugin commands should not overwrite other commands.")
        assert inspect.iscoroutinefunction(func), f"Plugin commands must be a coroutine: {name}"

        @command(s)
        @wraps(func)
        async def func_wrapper(*args, **kwargs):
            cmd_runner = args[0]  # type: Commands
            daemon = cmd_runner.daemon
            assert daemon is not None
            kwargs['plugin'] = daemon._plugins.get_plugin(plugin_name)
            return await func(*args, **kwargs)

        setattr(Commands, name, func_wrapper)
        return func_wrapper
    return decorator


def eval_bool(x: str) -> bool:
    if x == 'false':
        return False
    if x == 'true':
        return True
    # assume python, raise if malformed
    return bool(ast.literal_eval(x))


# don't use floats because of rounding errors
json_loads = lambda x: json.loads(x, parse_float=lambda x: str(to_decimal(x)))


def check_txid(txid):
    if not is_hash256_str(txid):
        raise UserFacingException(f"{repr(txid)} is not a txid")
    return txid


arg_types = {
    'int': int,
    'bool': eval_bool,
    'str': str,
    'txid': check_txid,
    'tx': convert_raw_tx_to_hex,
    'json': json_loads,
    'decimal': lambda x: str(to_decimal(x)),
    'decimal_or_dryrun': lambda x: str(to_decimal(x)) if x != 'dryrun' else x,
    'decimal_or_max': lambda x: str(to_decimal(x)) if not parse_max_spend(x) else x,
}

config_variables = {
    'addrequest': {
        'ssl_privkey': 'Path to your SSL private key, needed to sign the request.',
        'ssl_chain': 'Chain of SSL certificates, needed for signed requests. Put your certificate at the top and the root CA at the end',
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of bitcoin: URIs. Example: \"(\'file:///var/www/\',\'https://electrum.org/\')\"',
    },
    'listrequests': {
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of bitcoin: URIs. Example: \"(\'file:///var/www/\',\'https://electrum.org/\')\"',
    }
}


def set_default_subparser(self, name, args=None):
    """see http://stackoverflow.com/questions/5176691/argparse-how-to-specify-a-default-subcommand"""
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help', '--version']:  # global help/version if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)


argparse.ArgumentParser.set_default_subparser = set_default_subparser


# workaround https://bugs.python.org/issue23058
# see https://github.com/nickstenning/honcho/pull/121

def subparser_call(self, parser, namespace, values, option_string=None):
    from argparse import ArgumentError, SUPPRESS, _UNRECOGNIZED_ARGS_ATTR
    parser_name = values[0]
    arg_strings = values[1:]
    # set the parser name if requested
    if self.dest is not SUPPRESS:
        setattr(namespace, self.dest, parser_name)
    # select the parser
    try:
        parser = self._name_parser_map[parser_name]
    except KeyError:
        tup = parser_name, ', '.join(self._name_parser_map)
        msg = _('unknown parser {!r} (choices: {})').format(*tup)
        raise ArgumentError(self, msg)
    # parse all the remaining options into the namespace
    # store any unrecognized options on the object, so that the top
    # level parser can decide what to do with them
    namespace, arg_strings = parser.parse_known_args(arg_strings, namespace)
    if arg_strings:
        vars(namespace).setdefault(_UNRECOGNIZED_ARGS_ATTR, [])
        getattr(namespace, _UNRECOGNIZED_ARGS_ATTR).extend(arg_strings)


argparse._SubParsersAction.__call__ = subparser_call


def add_network_options(parser):
    group = parser.add_argument_group('network options')
    group.add_argument(
        "-f", "--serverfingerprint", dest=SimpleConfig.NETWORK_SERVERFINGERPRINT.key(), default=None,
        help="only allow connecting to servers with a matching SSL certificate SHA256 fingerprint. " +
        "To calculate this yourself: '$ openssl x509 -noout -fingerprint -sha256 -inform pem -in mycertfile.crt'. Enter as 64 hex chars.")
    group.add_argument(
        "-1", "--oneserver", action="store_true", dest=SimpleConfig.NETWORK_ONESERVER.key(), default=None,
        help="connect to one server only")
    group.add_argument(
        "-s", "--server", dest=SimpleConfig.NETWORK_SERVER.key(), default=None,
        help="set server host:port:protocol, where protocol is either t (tcp) or s (ssl)")
    group.add_argument(
        "-p", "--proxy", dest=SimpleConfig.NETWORK_PROXY.key(), default=None,
        help="set proxy [type:]host:port (or 'none' to disable proxy), where type is socks4 or socks5")
    group.add_argument(
        "--proxyuser", dest=SimpleConfig.NETWORK_PROXY_USER.key(), default=None,
        help="set proxy username")
    group.add_argument(
        "--proxypassword", dest=SimpleConfig.NETWORK_PROXY_PASSWORD.key(), default=None,
        help="set proxy password")
    group.add_argument(
        "--noonion", action="store_true", dest=SimpleConfig.NETWORK_NOONION.key(), default=None,
        help="do not try to connect to onion servers")
    group.add_argument(
        "--skipmerklecheck", action="store_true", dest=SimpleConfig.NETWORK_SKIPMERKLECHECK.key(), default=None,
        help="Tolerate invalid merkle proofs from Electrum server")


def add_global_options(parser, suppress=False):
    group = parser.add_argument_group('global options')
    group.add_argument(
        "-v", dest="verbosity", default='',
        help=argparse.SUPPRESS if suppress else "Set verbosity (log levels)")
    group.add_argument(
        "-D", "--dir", dest="electrum_path",
        help=argparse.SUPPRESS if suppress else "electrum directory")
    group.add_argument(
        "-w", "--wallet", dest="wallet_path",
        help=argparse.SUPPRESS if suppress else "wallet path")
    group.add_argument(
        "-P", "--portable", action="store_true", dest="portable", default=False,
        help=argparse.SUPPRESS if suppress else "Use local 'electrum_data' directory")
    for chain in constants.NETS_LIST:
        group.add_argument(
            f"--{chain.cli_flag()}", action="store_true", dest=chain.config_key(), default=False,
            help=argparse.SUPPRESS if suppress else f"Use {chain.NET_NAME} chain")
    group.add_argument(
        "-o", "--offline", action="store_true", dest=SimpleConfig.NETWORK_OFFLINE.key(), default=None,
        help=argparse.SUPPRESS if suppress else "Run offline")
    group.add_argument(
        "--rpcuser", dest=SimpleConfig.RPC_USERNAME.key(), default=argparse.SUPPRESS,
        help=argparse.SUPPRESS if suppress else "RPC user")
    group.add_argument(
        "--rpcpassword", dest=SimpleConfig.RPC_PASSWORD.key(), default=argparse.SUPPRESS,
        help=argparse.SUPPRESS if suppress else "RPC password")
    group.add_argument(
        "--forgetconfig", action="store_true", dest=SimpleConfig.CONFIG_FORGET_CHANGES.key(), default=False,
        help=argparse.SUPPRESS if suppress else "Forget config on exit")


def get_simple_parser():
    """ simple parser that figures out the path of the config file and ignore unknown args """
    from optparse import OptionParser, BadOptionError, AmbiguousOptionError

    class PassThroughOptionParser(OptionParser):
        # see https://stackoverflow.com/questions/1885161/how-can-i-get-optparses-optionparser-to-ignore-invalid-options
        def _process_args(self, largs, rargs, values):
            while rargs:
                try:
                    OptionParser._process_args(self, largs, rargs, values)
                except (BadOptionError, AmbiguousOptionError) as e:
                    largs.append(e.opt_str)

    parser = PassThroughOptionParser()
    parser.add_option("-D", "--dir", dest="electrum_path", help="electrum directory")
    parser.add_option("-P", "--portable", action="store_true", dest="portable", default=False, help="Use local 'electrum_data' directory")
    for chain in constants.NETS_LIST:
        parser.add_option(f"--{chain.cli_flag()}", action="store_true", dest=chain.config_key(), default=False, help=f"Use {chain.NET_NAME} chain")
    return parser


def get_parser():
    # create main parser
    parser = argparse.ArgumentParser(
        epilog="Run 'electrum help <command>' to see the help for a command")
    parser.add_argument("--version", dest="cmd", action='store_const', const='version', help="Return the version of Electrum.")
    add_global_options(parser)
    subparsers = parser.add_subparsers(dest='cmd', metavar='<command>')
    # gui
    parser_gui = subparsers.add_parser('gui', description="Run Electrum's Graphical User Interface.", help="Run GUI (default)")
    parser_gui.add_argument("url", nargs='?', default=None, help="bitcoin URI (or bip70 file)")
    parser_gui.add_argument("-g", "--gui", dest=SimpleConfig.GUI_NAME.key(), help="select graphical user interface", choices=['qt', 'text', 'stdio', 'qml'])
    parser_gui.add_argument("-m", action="store_true", dest=SimpleConfig.GUI_QT_HIDE_ON_STARTUP.key(), default=False, help="hide GUI on startup")
    parser_gui.add_argument("-L", "--lang", dest=SimpleConfig.LOCALIZATION_LANGUAGE.key(), default=None, help="default language used in GUI")
    parser_gui.add_argument("--daemon", action="store_true", dest="daemon", default=False, help="keep daemon running after GUI is closed")
    parser_gui.add_argument("--nosegwit", action="store_true", dest=SimpleConfig.WIZARD_DONT_CREATE_SEGWIT.key(), default=False, help="Do not create segwit wallets")
    add_network_options(parser_gui)
    add_global_options(parser_gui)
    # daemon
    parser_daemon = subparsers.add_parser('daemon', help="Run Daemon")
    parser_daemon.add_argument("-d", "--detached", action="store_true", dest="detach", default=False, help="run daemon in detached mode")
    # FIXME: all these options are rpc-server-side. The CLI client-side cannot use e.g. --rpcport,
    #        instead it reads it from the daemon lockfile.
    parser_daemon.add_argument("--rpchost", dest=SimpleConfig.RPC_HOST.key(), default=argparse.SUPPRESS, help="RPC host")
    parser_daemon.add_argument("--rpcport", dest=SimpleConfig.RPC_PORT.key(), type=int, default=argparse.SUPPRESS, help="RPC port")
    parser_daemon.add_argument("--rpcsock", dest=SimpleConfig.RPC_SOCKET_TYPE.key(), default=None, help="what socket type to which to bind RPC daemon", choices=['unix', 'tcp', 'auto'])
    parser_daemon.add_argument("--rpcsockpath", dest=SimpleConfig.RPC_SOCKET_FILEPATH.key(), help="where to place RPC file socket")
    add_network_options(parser_daemon)
    add_global_options(parser_daemon)
    # commands
    for cmdname in sorted(known_commands.keys()):
        cmd = known_commands[cmdname]
        p = subparsers.add_parser(
            cmdname,
            description=cmd.description,
            help=cmd.short_description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="Run 'electrum -h' to see the list of global options",
        )
        for optname, default in zip(cmd.options, cmd.defaults):
            if optname in ['wallet_path', 'wallet', 'plugin']:
                continue
            if optname == 'password':
                p.add_argument("--password", dest='password', help="Wallet password. Use '--password :' if you want a prompt.")
                continue
            help = cmd.arg_descriptions.get(optname)
            if not help:
                print(f'undocumented argument {cmdname}::{optname}', file=sys.stderr)
            action = "store_true" if default is False else 'store'
            if action == 'store':
                type_descriptor = cmd.arg_types.get(optname)
                _type = arg_types.get(type_descriptor, str)
                p.add_argument('--' + optname, dest=optname, action=action, default=default, help=help, type=_type)
            else:
                p.add_argument('--' + optname, dest=optname, action=action, default=default, help=help)
        add_global_options(p, suppress=True)

        for param in cmd.params:
            if param in ['wallet_path', 'wallet']:
                continue
            help = cmd.arg_descriptions.get(param)
            if not help:
                print(f'undocumented argument {cmdname}::{param}', file=sys.stderr)
            type_descriptor = cmd.arg_types.get(param)
            _type = arg_types.get(type_descriptor)
            if help is not None and _type is None:
                print(f'unknown type \'{_type}\' for {cmdname}::{param}', file=sys.stderr)
            p.add_argument(param, help=help, type=_type)

        cvh = config_variables.get(cmdname)
        if cvh:
            group = p.add_argument_group('configuration variables', '(set with setconfig/getconfig)')
            for k, v in cvh.items():
                group.add_argument(k, nargs='?', help=v)

    # 'gui' is the default command
    # note: set_default_subparser modifies sys.argv
    parser.set_default_subparser('gui')
    return parser
