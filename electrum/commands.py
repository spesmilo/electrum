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

import sys
import datetime
import copy
import argparse
import json
import ast
import base64
import operator
import asyncio
import inspect
from collections import defaultdict
from functools import wraps, partial
from itertools import repeat
from decimal import Decimal, InvalidOperation
from typing import Optional, TYPE_CHECKING, Dict, List
import os

from .import util, ecc
from .util import (bfh, format_satoshis, json_decode, json_normalize,
                   is_hash256_str, is_hex_str, to_bytes, parse_max_spend, to_decimal,
                   UserFacingException)
from . import bitcoin
from .bitcoin import is_address,  hash_160, COIN
from .bip32 import BIP32Node
from .i18n import _
from .transaction import (Transaction, multisig_script, TxOutput, PartialTransaction, PartialTxOutput,
                          tx_from_any, PartialTxInput, TxOutpoint)
from . import transaction
from .invoices import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
from .synchronizer import Notifier
from .wallet import Abstract_Wallet, create_new_wallet, restore_wallet_from_text, Deterministic_Wallet, BumpFeeStrategy
from .address_synchronizer import TX_HEIGHT_LOCAL
from .mnemonic import Mnemonic
from .lnutil import SENT, RECEIVED
from .lnutil import LnFeatures
from .lnutil import extract_nodeid
from .lnpeer import channel_id_from_funding_tx
from .plugin import run_hook, DeviceMgr, Plugins
from .version import ELECTRUM_VERSION
from .simple_config import SimpleConfig
from .invoices import Invoice
from . import submarine_swaps
from . import GuiImportError
from . import crypto
from . import constants
from . import descriptor

if TYPE_CHECKING:
    from .network import Network
    from .daemon import Daemon


known_commands = {}  # type: Dict[str, Command]


class NotSynchronizedException(UserFacingException):
    pass


def satoshis_or_max(amount):
    return satoshis(amount) if not parse_max_spend(amount) else amount

def satoshis(amount):
    # satoshi conversion must not be performed by the parser
    return int(COIN*to_decimal(amount)) if amount is not None else None

def format_satoshis(x):
    return str(to_decimal(x)/COIN) if x is not None else None


class Command:
    def __init__(self, func, s):
        self.name = func.__name__
        self.requires_network = 'n' in s
        self.requires_wallet = 'w' in s
        self.requires_password = 'p' in s
        self.requires_lightning = 'l' in s
        self.description = func.__doc__
        self.help = self.description.split('.')[0] if self.description else None
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
                assert varname in self.options
        assert not ('wallet_path' in varnames and 'wallet' in varnames)
        if self.requires_wallet:
            assert 'wallet' in varnames


def command(s):
    def decorator(func):
        global known_commands
        name = func.__name__
        known_commands[name] = Command(func, s)
        @wraps(func)
        async def func_wrapper(*args, **kwargs):
            cmd_runner = args[0]  # type: Commands
            cmd = known_commands[func.__name__]  # type: Command
            password = kwargs.get('password')
            daemon = cmd_runner.daemon
            if daemon:
                if 'wallet_path' in cmd.options and kwargs.get('wallet_path') is None:
                    kwargs['wallet_path'] = daemon.config.get_wallet_path()
                if cmd.requires_wallet and kwargs.get('wallet') is None:
                    kwargs['wallet'] = daemon.config.get_wallet_path()
                if 'wallet' in cmd.options:
                    wallet = kwargs.get('wallet', None)
                    if isinstance(wallet, str):
                        wallet = daemon.get_wallet(wallet)
                        if wallet is None:
                            raise UserFacingException('wallet not loaded')
                        kwargs['wallet'] = wallet
                    if cmd.requires_password and password is None and wallet.has_password():
                        password = wallet.get_unlocked_password()
                        if password:
                            kwargs['password'] = password
                        else:
                            raise UserFacingException('Password required. Unlock the wallet, or add a --password option to your command')
            wallet = kwargs.get('wallet')  # type: Optional[Abstract_Wallet]
            if cmd.requires_wallet and not wallet:
                raise UserFacingException('wallet not loaded')
            if cmd.requires_password and password is None and wallet.has_password():
                raise UserFacingException('Password required')
            if cmd.requires_lightning and (not wallet or not wallet.has_lightning()):
                raise UserFacingException('Lightning not enabled in this wallet')
            return await func(*args, **kwargs)
        return func_wrapper
    return decorator


class Commands:

    def __init__(self, *, config: 'SimpleConfig',
                 network: 'Network' = None,
                 daemon: 'Daemon' = None, callback=None):
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

    @command('')
    async def commands(self):
        """List of commands"""
        return ' '.join(sorted(known_commands.keys()))

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
            'default_wallet': self.config.get_wallet_path(),
            'fee_per_kb': self.config.fee_per_kb(),
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
                'path': path,
                'synchronized': w.is_up_to_date(),
                'unlocked': w.has_password() and (w.get_unlocked_password() is not None),
            }
            for path, w in self.daemon.get_wallets().items()
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

    @command('n')
    async def close_wallet(self, wallet_path=None):
        """Close wallet"""
        return await self.daemon._stop_wallet(wallet_path)

    @command('')
    async def create(self, passphrase=None, password=None, encrypt_file=True, seed_type=None, wallet_path=None):
        """Create a new wallet.
        If you want to be prompted for an argument, type '?' or ':' (concealed)
        """
        d = create_new_wallet(path=wallet_path,
                              passphrase=passphrase,
                              password=password,
                              encrypt_file=encrypt_file,
                              seed_type=seed_type,
                              config=self.config)
        return {
            'seed': d['seed'],
            'path': d['wallet'].storage.path,
            'msg': d['msg'],
        }

    @command('')
    async def restore(self, text, passphrase=None, password=None, encrypt_file=True, wallet_path=None):
        """Restore a wallet from text. Text can be a seed phrase, a master
        public key, a master private key, a list of bitcoin addresses
        or bitcoin private keys.
        If you want to be prompted for an argument, type '?' or ':' (concealed)
        """
        # TODO create a separate command that blocks until wallet is synced
        d = restore_wallet_from_text(text,
                                     path=wallet_path,
                                     passphrase=passphrase,
                                     password=password,
                                     encrypt_file=encrypt_file,
                                     config=self.config)
        return {
            'path': d['wallet'].storage.path,
            'msg': d['msg'],
        }

    @command('wp')
    async def password(self, password=None, new_password=None, encrypt_file=None, wallet: Abstract_Wallet = None):
        """Change wallet password. """
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
        return {'password':wallet.has_password()}

    @command('w')
    async def get(self, key, wallet: Abstract_Wallet = None):
        """Return item from wallet storage"""
        return wallet.db.get(key)

    @command('')
    async def getconfig(self, key):
        """Return a configuration variable. """
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

    @command('')
    async def setconfig(self, key, value):
        """Set a configuration variable. 'value' may be a string or a Python expression."""
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
    async def make_seed(self, nbits=None, language=None, seed_type=None):
        """Create a seed"""
        from .mnemonic import Mnemonic
        s = Mnemonic(language).make_seed(seed_type=seed_type, num_bits=nbits)
        return s

    @command('n')
    async def getaddresshistory(self, address):
        """Return the transaction history of any address. Note: This is a
        walletless server query, results are not checked by SPV.
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
            d["value"] = str(to_decimal(v)/COIN) if v is not None else None
            coins.append(d)
        return coins

    @command('n')
    async def getaddressunspent(self, address):
        """Returns the UTXO list of any address. Note: This
        is a walletless server query, results are not checked by SPV.
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
        """Sign a transaction. The provided list of private keys will be used to sign the transaction."""
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
    async def signtransaction(self, tx, password=None, wallet: Abstract_Wallet = None, iknowwhatimdoing: bool=False):
        """Sign a transaction. The wallet keys will be used to sign the transaction."""
        tx = tx_from_any(tx)
        wallet.sign_transaction(tx, password, ignore_warnings=iknowwhatimdoing)
        return tx.serialize()

    @command('')
    async def deserialize(self, tx):
        """Deserialize a serialized transaction"""
        tx = tx_from_any(tx)
        return tx.to_json()

    @command('n')
    async def broadcast(self, tx):
        """Broadcast a transaction to the network. """
        tx = Transaction(tx)
        await self.network.broadcast_transaction(tx)
        return tx.txid()

    @command('')
    async def createmultisig(self, num, pubkeys):
        """Create multisig address"""
        assert isinstance(pubkeys, list), (type(num), type(pubkeys))
        redeem_script = multisig_script(pubkeys, num)
        address = bitcoin.hash160_to_p2sh(hash_160(redeem_script))
        return {'address': address, 'redeemScript': redeem_script.hex()}

    @command('w')
    async def freeze(self, address: str, wallet: Abstract_Wallet = None):
        """Freeze address. Freeze the funds at one of your wallet\'s addresses"""
        return wallet.set_frozen_state_of_addresses([address], True)

    @command('w')
    async def unfreeze(self, address: str, wallet: Abstract_Wallet = None):
        """Unfreeze address. Unfreeze the funds at one of your wallet\'s address"""
        return wallet.set_frozen_state_of_addresses([address], False)

    @command('w')
    async def freeze_utxo(self, coin: str, wallet: Abstract_Wallet = None):
        """Freeze a UTXO so that the wallet will not spend it."""
        wallet.set_frozen_state_of_coins([coin], True)
        return True

    @command('w')
    async def unfreeze_utxo(self, coin: str, wallet: Abstract_Wallet = None):
        """Unfreeze a UTXO so that the wallet might spend it."""
        wallet.set_frozen_state_of_coins([coin], False)
        return True

    @command('wp')
    async def getprivatekeys(self, address, password=None, wallet: Abstract_Wallet = None):
        """Get private keys of addresses. You may pass a single wallet address, or a list of wallet addresses."""
        if isinstance(address, str):
            address = address.strip()
        if is_address(address):
            return wallet.export_private_key(address, password)
        domain = address
        return [wallet.export_private_key(address, password) for address in domain]

    @command('wp')
    async def getprivatekeyforpath(self, path, password=None, wallet: Abstract_Wallet = None):
        """Get private key corresponding to derivation path (address index).
        'path' can be either a str such as "m/0/50", or a list of ints such as [0, 50].
        """
        return wallet.export_private_key_for_path(path, password)

    @command('w')
    async def ismine(self, address, wallet: Abstract_Wallet = None):
        """Check if address is in wallet. Return true if and only address is in wallet"""
        return wallet.is_mine(address)

    @command('')
    async def dumpprivkeys(self):
        """Deprecated."""
        return "This command is deprecated. Use a pipe instead: 'electrum listaddresses | electrum getprivatekeys - '"

    @command('')
    async def validateaddress(self, address):
        """Check that an address is valid. """
        return is_address(address)

    @command('w')
    async def getpubkeys(self, address, wallet: Abstract_Wallet = None):
        """Return the public keys for a wallet address. """
        return wallet.get_public_keys(address)

    @command('w')
    async def getbalance(self, wallet: Abstract_Wallet = None):
        """Return the balance of your wallet. """
        c, u, x = wallet.get_balance()
        l = wallet.lnworker.get_balance() if wallet.lnworker else None
        out = {"confirmed": str(to_decimal(c)/COIN)}
        if u:
            out["unconfirmed"] = str(to_decimal(u)/COIN)
        if x:
            out["unmatured"] = str(to_decimal(x)/COIN)
        if l:
            out["lightning"] = str(to_decimal(l)/COIN)
        return out

    @command('n')
    async def getaddressbalance(self, address):
        """Return the balance of any address. Note: This is a walletless
        server query, results are not checked by SPV.
        """
        sh = bitcoin.address_to_scripthash(address)
        out = await self.network.get_balance_for_scripthash(sh)
        out["confirmed"] =  str(to_decimal(out["confirmed"])/COIN)
        out["unconfirmed"] =  str(to_decimal(out["unconfirmed"])/COIN)
        return out

    @command('n')
    async def getmerkle(self, txid, height):
        """Get Merkle branch of a transaction included in a block. Electrum
        uses this to verify transactions (Simple Payment Verification)."""
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
        from . import ecc_fast
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
        """Convert xtype of a master key. e.g. xpub -> ypub"""
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
        """Import a private key."""
        if not wallet.can_import_privkey():
            return "Error: This type of wallet cannot import private keys. Try to create a new wallet with that key."
        try:
            addr = wallet.import_private_key(privkey, password)
            out = "Keypair imported: " + addr
        except Exception as e:
            out = "Error: " + repr(e)
        return out

    def _resolver(self, x, wallet: Abstract_Wallet):
        if x is None:
            return None
        out = wallet.contacts.resolve(x)
        if out.get('type') == 'openalias' and self.nocheck is False and out.get('validated') is False:
            raise UserFacingException(f"cannot verify alias: {x}")
        return out['address']

    @command('n')
    async def sweep(self, privkey, destination, fee=None, nocheck=False, imax=100):
        """Sweep private keys. Returns a transaction that spends UTXOs from
        privkey to a destination address. The transaction is not
        broadcasted."""
        from .wallet import sweep
        tx_fee = satoshis(fee)
        privkeys = privkey.split()
        self.nocheck = nocheck
        #dest = self._resolver(destination)
        tx = await sweep(
            privkeys,
            network=self.network,
            config=self.config,
            to_address=destination,
            fee=tx_fee,
            imax=imax,
        )
        return tx.serialize() if tx else None

    @command('wp')
    async def signmessage(self, address, message, password=None, wallet: Abstract_Wallet = None):
        """Sign a message with a key. Use quotes if your message contains
        whitespaces"""
        sig = wallet.sign_message(address, message, password)
        return base64.b64encode(sig).decode('ascii')

    @command('')
    async def verifymessage(self, address, signature, message):
        """Verify a signature."""
        sig = base64.b64decode(signature)
        message = util.to_bytes(message)
        return bitcoin.verify_usermessage_with_address(address, sig, message)

    @command('wp')
    async def payto(self, destination, amount, fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None,
                    nocheck=False, unsigned=False, rbf=True, password=None, locktime=None, addtransaction=False, wallet: Abstract_Wallet = None):
        """Create a transaction. """
        self.nocheck = nocheck
        tx_fee = satoshis(fee)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = self._resolver(change_addr, wallet)
        domain_addr = None if domain_addr is None else map(self._resolver, domain_addr, repeat(wallet))
        amount_sat = satoshis_or_max(amount)
        outputs = [PartialTxOutput.from_address_and_value(destination, amount_sat)]
        tx = wallet.create_transaction(
            outputs,
            fee=tx_fee,
            feerate=feerate,
            change_addr=change_addr,
            domain_addr=domain_addr,
            domain_coins=domain_coins,
            sign=not unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime)
        result = tx.serialize()
        if addtransaction:
            await self.addtransaction(result, wallet=wallet)
        return result

    @command('wp')
    async def paytomany(self, outputs, fee=None, feerate=None, from_addr=None, from_coins=None, change_addr=None,
                        nocheck=False, unsigned=False, rbf=True, password=None, locktime=None, addtransaction=False, wallet: Abstract_Wallet = None):
        """Create a multi-output transaction. """
        self.nocheck = nocheck
        tx_fee = satoshis(fee)
        domain_addr = from_addr.split(',') if from_addr else None
        domain_coins = from_coins.split(',') if from_coins else None
        change_addr = self._resolver(change_addr, wallet)
        domain_addr = None if domain_addr is None else map(self._resolver, domain_addr, repeat(wallet))
        final_outputs = []
        for address, amount in outputs:
            address = self._resolver(address, wallet)
            amount_sat = satoshis_or_max(amount)
            final_outputs.append(PartialTxOutput.from_address_and_value(address, amount_sat))
        tx = wallet.create_transaction(
            final_outputs,
            fee=tx_fee,
            feerate=feerate,
            change_addr=change_addr,
            domain_addr=domain_addr,
            domain_coins=domain_coins,
            sign=not unsigned,
            rbf=rbf,
            password=password,
            locktime=locktime)
        result = tx.serialize()
        if addtransaction:
            await self.addtransaction(result, wallet=wallet)
        return result

    @command('w')
    async def onchain_history(self, year=None, show_addresses=False, show_fiat=False, wallet: Abstract_Wallet = None,
                              from_height=None, to_height=None):
        """Wallet onchain history. Returns the transaction history of your wallet."""
        kwargs = {
            'show_addresses': show_addresses,
            'from_height': from_height,
            'to_height': to_height,
        }
        if year:
            import time
            start_date = datetime.datetime(year, 1, 1)
            end_date = datetime.datetime(year+1, 1, 1)
            kwargs['from_timestamp'] = time.mktime(start_date.timetuple())
            kwargs['to_timestamp'] = time.mktime(end_date.timetuple())
        if show_fiat:
            from .exchange_rate import FxThread
            kwargs['fx'] = self.daemon.fx if self.daemon else FxThread(config=self.config)

        return json_normalize(wallet.get_detailed_history(**kwargs))

    @command('wp')
    async def bumpfee(self, tx, new_fee_rate, from_coins=None, decrease_payment=False, password=None, unsigned=False, wallet: Abstract_Wallet = None):
        """Bump the fee for an unconfirmed transaction.
        'tx' can be either a raw hex tx or a txid. If txid, the corresponding tx must already be part of the wallet history.
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

    @command('wl')
    async def lightning_history(self, show_fiat=False, wallet: Abstract_Wallet = None):
        """ lightning history """
        lightning_history = wallet.lnworker.get_history() if wallet.lnworker else []
        return json_normalize(lightning_history)

    @command('w')
    async def setlabel(self, key, label, wallet: Abstract_Wallet = None):
        """Assign a label to an item. Item may be a bitcoin address or a
        transaction ID"""
        wallet.set_label(key, label)

    @command('w')
    async def listcontacts(self, wallet: Abstract_Wallet = None):
        """Show your list of contacts"""
        return wallet.contacts

    @command('w')
    async def getalias(self, key, wallet: Abstract_Wallet = None):
        """Retrieve alias. Lookup in your list of contacts, and for an OpenAlias DNS record."""
        return wallet.contacts.resolve(key)

    @command('w')
    async def searchcontacts(self, query, wallet: Abstract_Wallet = None):
        """Search through contacts, return matching entries. """
        results = {}
        for key, value in wallet.contacts.items():
            if query.lower() in key.lower():
                results[key] = value
        return results

    @command('w')
    async def listaddresses(self, receiving=False, change=False, labels=False, frozen=False, unused=False, funded=False, balance=False, wallet: Abstract_Wallet = None):
        """List wallet addresses. Returns the list of all addresses in your wallet. Use optional arguments to filter the results."""
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
        """Retrieve a transaction. """
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
        """Encrypt a message with a public key. Use quotes if the message contains whitespaces."""
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
        """Decrypt a message encrypted with a public key."""
        if not is_hex_str(pubkey):
            raise UserFacingException(f"pubkey must be a hex string instead of {repr(pubkey)}")
        if not isinstance(encrypted, (str, bytes, bytearray)):
            raise UserFacingException(f"encrypted must be a string-like object instead of {repr(encrypted)}")
        decrypted = wallet.decrypt_message(pubkey, encrypted, password)
        return decrypted.decode('utf-8')

    @command('w')
    async def get_request(self, request_id, wallet: Abstract_Wallet = None):
        """Returns a payment request"""
        r = wallet.get_request(request_id)
        if not r:
            raise UserFacingException("Request not found")
        return wallet.export_request(r)

    @command('w')
    async def get_invoice(self, invoice_id, wallet: Abstract_Wallet = None):
        """Returns an invoice (request for outgoing payment)"""
        r = wallet.get_invoice(invoice_id)
        if not r:
            raise UserFacingException("Request not found")
        return wallet.export_invoice(r)

    #@command('w')
    #async def ackrequest(self, serialized):
    #    """<Not implemented>"""
    #    pass

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
        """Returns the list of incoming payment requests saved in the wallet."""
        l = wallet.get_sorted_requests()
        l = self._filter_invoices(l, wallet, pending, expired, paid)
        return [wallet.export_request(x) for x in l]

    @command('w')
    async def list_invoices(self, pending=False, expired=False, paid=False, wallet: Abstract_Wallet = None):
        """Returns the list of invoices (requests for outgoing payments) saved in the wallet."""
        l = wallet.get_invoices()
        l = self._filter_invoices(l, wallet, pending, expired, paid)
        return [wallet.export_invoice(x) for x in l]

    @command('w')
    async def createnewaddress(self, wallet: Abstract_Wallet = None):
        """Create a new receiving address, beyond the gap limit of the wallet"""
        return wallet.create_new_address(False)

    @command('w')
    async def changegaplimit(self, new_limit, iknowwhatimdoing=False, wallet: Abstract_Wallet = None):
        """Change the gap limit of the wallet."""
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
    async def add_request(self, amount, memo='', expiry=3600, force=False, wallet: Abstract_Wallet = None):
        """Create a payment request, using the first unused address of the wallet.
        The address will be considered as used after this operation.
        If no payment is received, the address will be considered as unused if the payment request is deleted from the wallet."""
        addr = wallet.get_unused_address()
        if addr is None:
            if force:
                addr = wallet.create_new_address(False)
            else:
                return False
        amount = satoshis(amount)
        expiry = int(expiry) if expiry else None
        key = wallet.create_request(amount, memo, expiry, addr)
        req = wallet.get_request(key)
        return wallet.export_request(req)

    @command('w')
    async def addtransaction(self, tx, wallet: Abstract_Wallet = None):
        """ Add a transaction to the wallet history """
        tx = Transaction(tx)
        if not wallet.adb.add_transaction(tx):
            return False
        wallet.save_db()
        return tx.txid()

    @command('w')
    async def delete_request(self, request_id, wallet: Abstract_Wallet = None):
        """Remove an incoming payment request"""
        return wallet.delete_request(request_id)

    @command('w')
    async def delete_invoice(self, invoice_id, wallet: Abstract_Wallet = None):
        """Remove an outgoing payment invoice"""
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
        """Watch an address. Every time the address changes, a http POST is sent to the URL.
        Call with an empty URL to stop watching an address.
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

    @command('')
    async def getfeerate(self):
        """Return current fee rate settings and current estimate (in sat/kvByte).
        """
        method, value, feerate, tooltip = self.config.getfeerate()
        return {
            'method': method,
            'value': value,
            'sat/kvB': feerate,
            'tooltip': tooltip,
        }

    @command('')
    async def setfeerate(self, method, value):
        """Set fee rate estimation method and value"""
        self.config.setfeerate(method, value)

    @command('w')
    async def removelocaltx(self, txid, wallet: Abstract_Wallet = None):
        """Remove a 'local' transaction from the wallet, and its dependent
        transactions.
        """
        if not is_hash256_str(txid):
            raise UserFacingException(f"{repr(txid)} is not a txid")
        height = wallet.adb.get_tx_height(txid).height
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
        """
        if not is_hash256_str(txid):
            raise UserFacingException(f"{repr(txid)} is not a txid")
        if not wallet.db.get_transaction(txid):
            raise UserFacingException("Transaction not in wallet.")
        return {
            "confirmations": wallet.adb.get_tx_height(txid).conf,
        }

    @command('')
    async def help(self):
        # for the python console
        return sorted(known_commands.keys())

    # lightning network commands
    @command('wnl')
    async def add_peer(self, connection_string, timeout=20, gossip=False, wallet: Abstract_Wallet = None):
        lnworker = self.network.lngossip if gossip else wallet.lnworker
        await lnworker.add_peer(connection_string)
        return True

    @command('wnl')
    async def list_peers(self, gossip=False, wallet: Abstract_Wallet = None):
        lnworker = self.network.lngossip if gossip else wallet.lnworker
        return [{
            'node_id':p.pubkey.hex(),
            'address':p.transport.name(),
            'initialized':p.is_initialized(),
            'features': str(LnFeatures(p.features)),
            'channels': [c.funding_outpoint.to_str() for c in p.channels.values()],
        } for p in lnworker.peers.values()]

    @command('wpnl')
    async def open_channel(self, connection_string, amount, push_amount=0, public=False, zeroconf=False, password=None, wallet: Abstract_Wallet = None):
        funding_sat = satoshis(amount)
        push_sat = satoshis(push_amount)
        peer = await wallet.lnworker.add_peer(connection_string)
        chan, funding_tx = await wallet.lnworker.open_channel_with_peer(
            peer, funding_sat,
            push_sat=push_sat,
            public=public,
            zeroconf=zeroconf,
            password=password)
        return chan.funding_outpoint.to_str()

    @command('')
    async def decode_invoice(self, invoice: str):
        invoice = Invoice.from_bech32(invoice)
        return invoice.to_debug_json()

    @command('wnl')
    async def lnpay(self, invoice, timeout=120, wallet: Abstract_Wallet = None):
        lnworker = wallet.lnworker
        lnaddr = lnworker._check_invoice(invoice)
        payment_hash = lnaddr.paymenthash
        wallet.save_invoice(Invoice.from_bech32(invoice))
        success, log = await lnworker.pay_invoice(invoice)
        return {
            'payment_hash': payment_hash.hex(),
            'success': success,
            'preimage': lnworker.get_preimage(payment_hash).hex() if success else None,
            'log': [x.formatted_tuple() for x in log]
        }

    @command('wl')
    async def nodeid(self, wallet: Abstract_Wallet = None):
        listen_addr = self.config.LIGHTNING_LISTEN
        return wallet.lnworker.node_keypair.pubkey.hex() + (('@' + listen_addr) if listen_addr else '')

    @command('wl')
    async def list_channels(self, wallet: Abstract_Wallet = None):
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
                'state': chan.get_state().name,
                'peer_state': chan.peer_state.name,
                'remote_pubkey': chan.node_id.hex(),
                'local_balance': chan.balance(LOCAL)//1000,
                'remote_balance': chan.balance(REMOTE)//1000,
                'local_ctn': chan.get_latest_ctn(LOCAL),
                'remote_ctn': chan.get_latest_ctn(REMOTE),
                'local_reserve': chan.config[REMOTE].reserve_sat, # their config has our reserve
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
                'state': chan.get_state().name,
            } for channel_id, chan in backups
        ]

    @command('wnl')
    async def enable_htlc_settle(self, b: bool, wallet: Abstract_Wallet = None):
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

    @command('wnl')
    async def close_channel(self, channel_point, force=False, wallet: Abstract_Wallet = None):
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        coro = wallet.lnworker.force_close_channel(chan_id) if force else wallet.lnworker.close_channel(chan_id)
        return await coro

    @command('wnl')
    async def request_force_close(self, channel_point, connection_string=None, wallet: Abstract_Wallet = None):
        """
        Requests the remote to force close a channel.
        If a connection string is passed, can be used without having state or any backup for the channel.
        Assumes that channel was originally opened with the same local peer (node_keypair).
        """
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        await wallet.lnworker.request_force_close(chan_id, connect_str=connection_string)

    @command('wl')
    async def export_channel_backup(self, channel_point, wallet: Abstract_Wallet = None):
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        return wallet.lnworker.export_channel_backup(chan_id)

    @command('wl')
    async def import_channel_backup(self, encrypted, wallet: Abstract_Wallet = None):
        return wallet.lnworker.import_channel_backup(encrypted)

    @command('wnl')
    async def get_channel_ctx(self, channel_point, iknowwhatimdoing=False, wallet: Abstract_Wallet = None):
        """ return the current commitment transaction of a channel """
        if not iknowwhatimdoing:
            raise UserFacingException(
                "WARNING: this command is potentially unsafe.\n"
                "To proceed, try again, with the --iknowwhatimdoing option.")
        txid, index = channel_point.split(':')
        chan_id, _ = channel_id_from_funding_tx(txid, int(index))
        chan = wallet.lnworker.channels[chan_id]
        tx = chan.force_close_tx()
        return tx.serialize()

    @command('wnl')
    async def get_watchtower_ctn(self, channel_point, wallet: Abstract_Wallet = None):
        """ return the local watchtower's ctn of channel. used in regtests """
        return await self.network.local_watchtower.sweepstore.get_ctn(channel_point, None)

    @command('wnl')
    async def rebalance_channels(self, from_scid, dest_scid, amount, wallet: Abstract_Wallet = None):
        """
        Rebalance channels.
        If trampoline is used, channels must be with different trampolines.
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

    @command('wnpl')
    async def normal_swap(self, onchain_amount, lightning_amount, password=None, wallet: Abstract_Wallet = None):
        """
        Normal submarine swap: send on-chain BTC, receive on Lightning
        Note that your funds will be locked for 24h if you do not have enough incoming capacity.
        """
        sm = wallet.lnworker.swap_manager
        if lightning_amount == 'dryrun':
            await sm.get_pairs()
            onchain_amount_sat = satoshis(onchain_amount)
            lightning_amount_sat = sm.get_recv_amount(onchain_amount_sat, is_reverse=False)
            txid = None
        elif onchain_amount == 'dryrun':
            await sm.get_pairs()
            lightning_amount_sat = satoshis(lightning_amount)
            onchain_amount_sat = sm.get_send_amount(lightning_amount_sat, is_reverse=False)
            txid = None
        else:
            lightning_amount_sat = satoshis(lightning_amount)
            onchain_amount_sat = satoshis(onchain_amount)
            txid = await wallet.lnworker.swap_manager.normal_swap(
                lightning_amount_sat=lightning_amount_sat,
                expected_onchain_amount_sat=onchain_amount_sat,
                password=password,
            )
        return {
            'txid': txid,
            'lightning_amount': format_satoshis(lightning_amount_sat),
            'onchain_amount': format_satoshis(onchain_amount_sat),
        }

    @command('wnl')
    async def reverse_swap(self, lightning_amount, onchain_amount, wallet: Abstract_Wallet = None):
        """Reverse submarine swap: send on Lightning, receive on-chain
        """
        sm = wallet.lnworker.swap_manager
        if onchain_amount == 'dryrun':
            await sm.get_pairs()
            lightning_amount_sat = satoshis(lightning_amount)
            onchain_amount_sat = sm.get_recv_amount(lightning_amount_sat, is_reverse=True)
            funding_txid = None
        elif lightning_amount == 'dryrun':
            await sm.get_pairs()
            onchain_amount_sat = satoshis(onchain_amount)
            lightning_amount_sat = sm.get_send_amount(onchain_amount_sat, is_reverse=True)
            funding_txid = None
        else:
            lightning_amount_sat = satoshis(lightning_amount)
            claim_fee = sm.get_claim_fee()
            onchain_amount_sat = satoshis(onchain_amount) + claim_fee
            funding_txid = await wallet.lnworker.swap_manager.reverse_swap(
                lightning_amount_sat=lightning_amount_sat,
                expected_onchain_amount_sat=onchain_amount_sat,
            )
        return {
            'funding_txid': funding_txid,
            'lightning_amount': format_satoshis(lightning_amount_sat),
            'onchain_amount': format_satoshis(onchain_amount_sat),
        }

    @command('n')
    async def convert_currency(self, from_amount=1, from_ccy = '', to_ccy = ''):
        """Converts the given amount of currency to another using the
        configured exchange rate source.
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


def eval_bool(x: str) -> bool:
    if x == 'false': return False
    if x == 'true': return True
    try:
        return bool(ast.literal_eval(x))
    except Exception:
        return bool(x)

param_descriptions = {
    'privkey': 'Private key. Type \'?\' to get a prompt.',
    'destination': 'Bitcoin address, contact or alias',
    'address': 'Bitcoin address',
    'seed': 'Seed phrase',
    'txid': 'Transaction ID',
    'pos': 'Position',
    'height': 'Block height',
    'tx': 'Serialized transaction (hexadecimal)',
    'key': 'Variable name',
    'pubkey': 'Public key',
    'message': 'Clear text message. Use quotes if it contains spaces.',
    'encrypted': 'Encrypted message',
    'amount': 'Amount to be sent (in BTC). Type \'!\' to send the maximum available.',
    'outputs': 'list of ["address", amount]',
    'redeem_script': 'redeem script (hexadecimal)',
    'lightning_amount': "Amount sent or received in a submarine swap. Set it to 'dryrun' to receive a value",
    'onchain_amount': "Amount sent or received in a submarine swap. Set it to 'dryrun' to receive a value",
}

command_options = {
    'password':    ("-W", "Password. Use '--password :' if you want a prompt."),
    'new_password':(None, "New Password"),
    'encrypt_file':(None, "Whether the file on disk should be encrypted with the provided password"),
    'receiving':   (None, "Show only receiving addresses"),
    'change':      (None, "Show only change addresses"),
    'frozen':      (None, "Show only frozen addresses"),
    'unused':      (None, "Show only unused addresses"),
    'funded':      (None, "Show only funded addresses"),
    'balance':     ("-b", "Show the balances of listed addresses"),
    'labels':      ("-l", "Show the labels of listed addresses"),
    'nocheck':     (None, "Do not verify aliases"),
    'imax':        (None, "Maximum number of inputs"),
    'fee':         ("-f", "Transaction fee (absolute, in BTC)"),
    'feerate':     (None, f"Transaction fee rate (in {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE})"),
    'from_addr':   ("-F", "Source address (must be a wallet address; use sweep to spend from non-wallet address)."),
    'from_coins':  (None, "Source coins (must be in wallet; use sweep to spend from non-wallet address)."),
    'change_addr': ("-c", "Change address. Default is a spare address, or the source address if it's not in the wallet"),
    'nbits':       (None, "Number of bits of entropy"),
    'seed_type':   (None, "The type of seed to create, e.g. 'standard' or 'segwit'"),
    'language':    ("-L", "Default language for wordlist"),
    'passphrase':  (None, "Seed extension"),
    'privkey':     (None, "Private key. Set to '?' to get a prompt."),
    'unsigned':    ("-u", "Do not sign transaction"),
    'rbf':         (None, "Whether to signal opt-in Replace-By-Fee in the transaction (true/false)"),
    'decrease_payment': (None, "Whether payment amount will be decreased (true/false)"),
    'locktime':    (None, "Set locktime block number"),
    'addtransaction': (None,'Whether transaction is to be used for broadcasting afterwards. Adds transaction to the wallet'),
    'domain':      ("-D", "List of addresses"),
    'memo':        ("-m", "Description of the request"),
    'expiry':      (None, "Time in seconds"),
    'timeout':     (None, "Timeout in seconds"),
    'force':       (None, "Create new address beyond gap limit, if no more addresses are available."),
    'pending':     (None, "Show only pending requests."),
    'push_amount': (None, 'Push initial amount (in BTC)'),
    'zeroconf':    (None, 'request zeroconf channel'),
    'expired':     (None, "Show only expired requests."),
    'paid':        (None, "Show only paid requests."),
    'show_addresses': (None, "Show input and output addresses"),
    'show_fiat':   (None, "Show fiat value of transactions"),
    'show_fees':   (None, "Show miner fees paid by transactions"),
    'year':        (None, "Show history for a given year"),
    'from_height': (None, "Only show transactions that confirmed after given block height"),
    'to_height':   (None, "Only show transactions that confirmed before given block height"),
    'iknowwhatimdoing': (None, "Acknowledge that I understand the full implications of what I am about to do"),
    'gossip':      (None, "Apply command to gossip node instead of wallet"),
    'connection_string':      (None, "Lightning network node ID or network address"),
    'new_fee_rate': (None, f"The Updated/Increased Transaction fee rate (in {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE})"),
    'from_amount': (None, "Amount to convert (default: 1)"),
    'from_ccy':    (None, "Currency to convert from"),
    'to_ccy':      (None, "Currency to convert to"),
    'public':      (None, 'Channel will be announced'),
}


# don't use floats because of rounding errors
from .transaction import convert_raw_tx_to_hex
json_loads = lambda x: json.loads(x, parse_float=lambda x: str(to_decimal(x)))
arg_types = {
    'num': int,
    'nbits': int,
    'imax': int,
    'year': int,
    'from_height': int,
    'to_height': int,
    'tx': convert_raw_tx_to_hex,
    'pubkeys': json_loads,
    'jsontx': json_loads,
    'inputs': json_loads,
    'outputs': json_loads,
    'fee': lambda x: str(to_decimal(x)) if x is not None else None,
    'amount': lambda x: str(to_decimal(x)) if not parse_max_spend(x) else x,
    'locktime': int,
    'addtransaction': eval_bool,
    'encrypt_file': eval_bool,
    'rbf': eval_bool,
    'timeout': float,
}

config_variables = {

    'addrequest': {
        'ssl_privkey': 'Path to your SSL private key, needed to sign the request.',
        'ssl_chain': 'Chain of SSL certificates, needed for signed requests. Put your certificate at the top and the root CA at the end',
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of bitcoin: URIs. Example: \"(\'file:///var/www/\',\'https://electrum.org/\')\"',
    },
    'listrequests':{
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
    parser.add_argument("-f", "--serverfingerprint", dest=SimpleConfig.NETWORK_SERVERFINGERPRINT.key(), default=None,
                        help="only allow connecting to servers with a matching SSL certificate SHA256 fingerprint. " +
                             "To calculate this yourself: '$ openssl x509 -noout -fingerprint -sha256 -inform pem -in mycertfile.crt'. Enter as 64 hex chars.")
    parser.add_argument("-1", "--oneserver", action="store_true", dest=SimpleConfig.NETWORK_ONESERVER.key(), default=None,
                        help="connect to one server only")
    parser.add_argument("-s", "--server", dest=SimpleConfig.NETWORK_SERVER.key(), default=None,
                        help="set server host:port:protocol, where protocol is either t (tcp) or s (ssl)")
    parser.add_argument("-p", "--proxy", dest=SimpleConfig.NETWORK_PROXY.key(), default=None,
                        help="set proxy [type:]host:port (or 'none' to disable proxy), where type is socks4 or socks5")
    parser.add_argument("--proxyuser", dest=SimpleConfig.NETWORK_PROXY_USER.key(), default=None,
                        help="set proxy username")
    parser.add_argument("--proxypassword", dest=SimpleConfig.NETWORK_PROXY_PASSWORD.key(), default=None,
                        help="set proxy password")
    parser.add_argument("--noonion", action="store_true", dest=SimpleConfig.NETWORK_NOONION.key(), default=None,
                        help="do not try to connect to onion servers")
    parser.add_argument("--skipmerklecheck", action="store_true", dest=SimpleConfig.NETWORK_SKIPMERKLECHECK.key(), default=None,
                        help="Tolerate invalid merkle proofs from server")

def add_global_options(parser):
    group = parser.add_argument_group('global options')
    group.add_argument("-v", dest="verbosity", help="Set verbosity (log levels)", default='')
    group.add_argument("-V", dest="verbosity_shortcuts", help="Set verbosity (shortcut-filter list)", default='')
    group.add_argument("-D", "--dir", dest="electrum_path", help="electrum directory")
    group.add_argument("-P", "--portable", action="store_true", dest="portable", default=False, help="Use local 'electrum_data' directory")
    group.add_argument("--testnet", action="store_true", dest="testnet", default=False, help="Use Testnet")
    group.add_argument("--testnet4", action="store_true", dest="testnet4", default=False, help="Use Testnet4")
    group.add_argument("--regtest", action="store_true", dest="regtest", default=False, help="Use Regtest")
    group.add_argument("--simnet", action="store_true", dest="simnet", default=False, help="Use Simnet")
    group.add_argument("--signet", action="store_true", dest="signet", default=False, help="Use Signet")
    group.add_argument("-o", "--offline", action="store_true", dest=SimpleConfig.NETWORK_OFFLINE.key(), default=None, help="Run offline")
    group.add_argument("--rpcuser", dest=SimpleConfig.RPC_USERNAME.key(), default=argparse.SUPPRESS, help="RPC user")
    group.add_argument("--rpcpassword", dest=SimpleConfig.RPC_PASSWORD.key(), default=argparse.SUPPRESS, help="RPC password")

def add_wallet_option(parser):
    parser.add_argument("-w", "--wallet", dest="wallet_path", help="wallet path")
    parser.add_argument("--forgetconfig", action="store_true", dest=SimpleConfig.CONFIG_FORGET_CHANGES.key(), default=False, help="Forget config on exit")

def get_parser():
    # create main parser
    parser = argparse.ArgumentParser(
        epilog="Run 'electrum help <command>' to see the help for a command")
    parser.add_argument("--version", dest="cmd", action='store_const', const='version', help="Return the version of Electrum.")
    add_global_options(parser)
    add_wallet_option(parser)
    subparsers = parser.add_subparsers(dest='cmd', metavar='<command>')
    # gui
    parser_gui = subparsers.add_parser('gui', description="Run Electrum's Graphical User Interface.", help="Run GUI (default)")
    parser_gui.add_argument("url", nargs='?', default=None, help="bitcoin URI (or bip70 file)")
    parser_gui.add_argument("-g", "--gui", dest=SimpleConfig.GUI_NAME.key(), help="select graphical user interface", choices=['qt', 'text', 'stdio', 'qml'])
    parser_gui.add_argument("-m", action="store_true", dest=SimpleConfig.GUI_QT_HIDE_ON_STARTUP.key(), default=False, help="hide GUI on startup")
    parser_gui.add_argument("-L", "--lang", dest=SimpleConfig.LOCALIZATION_LANGUAGE.key(), default=None, help="default language used in GUI")
    parser_gui.add_argument("--daemon", action="store_true", dest="daemon", default=False, help="keep daemon running after GUI is closed")
    parser_gui.add_argument("--nosegwit", action="store_true", dest=SimpleConfig.WIZARD_DONT_CREATE_SEGWIT.key(), default=False, help="Do not create segwit wallets")
    add_wallet_option(parser_gui)
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
        p = subparsers.add_parser(cmdname, help=cmd.help, description=cmd.description)
        for optname, default in zip(cmd.options, cmd.defaults):
            if optname in ['wallet_path', 'wallet']:
                add_wallet_option(p)
                continue
            a, help = command_options[optname]
            b = '--' + optname
            action = "store_true" if default is False else 'store'
            args = (a, b) if a else (b,)
            if action == 'store':
                _type = arg_types.get(optname, str)
                p.add_argument(*args, dest=optname, action=action, default=default, help=help, type=_type)
            else:
                p.add_argument(*args, dest=optname, action=action, default=default, help=help)
        add_global_options(p)

        for param in cmd.params:
            if param in ['wallet_path', 'wallet']:
                continue
            h = param_descriptions.get(param, '')
            _type = arg_types.get(param, str)
            p.add_argument(param, help=h, type=_type)

        cvh = config_variables.get(cmdname)
        if cvh:
            group = p.add_argument_group('configuration variables', '(set with setconfig/getconfig)')
            for k, v in cvh.items():
                group.add_argument(k, nargs='?', help=v)

    # 'gui' is the default command
    parser.set_default_subparser('gui')
    return parser
