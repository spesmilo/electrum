import re
import time

from binascii import unhexlify
from struct import pack

from electrum.account import BIP32_Account
from electrum.bitcoin import (bc_address_to_hash_160, xpub_from_pubkey,
                              EncodeBase58Check)
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import (deserialize, is_extended_pubkey,
                                  Transaction, x_to_xpub)
from electrum.wallet import BIP32_HD_Wallet, BIP44_Wallet
from electrum.util import ThreadJob

class DeviceDisconnectedError(Exception):
    pass

class TrezorCompatibleWallet(BIP44_Wallet):
    # Extend BIP44 Wallet as required by hardware implementation.
    # Derived classes must set:
    #   - device
    #   - wallet_type

    restore_wallet_class = BIP44_Wallet

    def __init__(self, storage):
        BIP44_Wallet.__init__(self, storage)
        # This is set when paired with a device, and used to re-pair
        # a device that is disconnected and re-connected
        self.device_id = None
        # After timeout seconds we clear the device session
        self.session_timeout = storage.get('session_timeout', 180)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.handler = None

    def set_session_timeout(self, seconds):
        self.print_error("setting session timeout to %d seconds" % seconds)
        self.session_timeout = seconds
        self.storage.put('session_timeout', seconds)

    def disconnected(self):
        self.print_error("disconnected")
        self.handler.watching_only_changed()

    def connected(self):
        self.print_error("connected")
        self.handler.watching_only_changed()

    def wiped(self):
        self.print_error("wiped")
        self.handler.watching_only_changed()

    def timeout(self):
        self.print_error("timed out")

    def get_action(self):
        pass

    def can_create_accounts(self):
        return True

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is watching-only if its trezor device is not connected,
        or if it is connected but uninitialized.'''
        assert not self.has_seed()
        client = self.plugin.lookup_client(self)
        return not (client and client.is_initialized())

    def can_change_password(self):
        return False

    def client(self):
        return self.plugin.client(self)

    def derive_xkeys(self, root, derivation, password):
        if self.master_public_keys.get(root):
            return BIP44_wallet.derive_xkeys(self, root, derivation, password)

        # When creating a wallet we need to ask the device for the
        # master public key
        derivation = derivation.replace(self.root_name, self.prefix() + "/")
        xpub = self.get_public_key(derivation)
        return xpub, None

    def get_public_key(self, bip32_path):
        client = self.client()
        address_n = client.expand_path(bip32_path)
        node = client.get_public_node(address_n).node
        xpub = ("0488B21E".decode('hex') + chr(node.depth)
                + self.i4b(node.fingerprint) + self.i4b(node.child_num)
                + node.chain_code + node.public_key)
        return EncodeBase58Check(xpub)

    def i4b(self, x):
        return pack('>I', x)

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Decrypt method is not implemented'))

    def sign_message(self, address, message, password):
        client = self.client()
        address_path = self.address_id(address)
        address_n = client.expand_path(address_path)
        msg_sig = client.sign_message('Bitcoin', address_n, message)
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete() or self.is_watching_only():
            return
        # previous transactions used as inputs
        prev_tx = {}
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs:
            tx_hash = txin['prevout_hash']

            ptx = self.transactions.get(tx_hash)
            if ptx is None:
                ptx = self.network.synchronous_get(('blockchain.transaction.get', [tx_hash]))
                ptx = Transaction(ptx)
            prev_tx[tx_hash] = ptx

            for x_pubkey in txin['x_pubkeys']:
                if not is_extended_pubkey(x_pubkey):
                    continue
                xpub = x_to_xpub(x_pubkey)
                for k, v in self.master_public_keys.items():
                    if v == xpub:
                        acc_id = re.match("x/(\d+)'", k).group(1)
                        xpub_path[xpub] = self.account_derivation(acc_id)

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)


class TrezorCompatiblePlugin(BasePlugin, ThreadJob):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    # This plugin automatically keeps track of attached devices, and
    # connects to anything attached creating a new Client instance.
    # When disconnected, the client is informed via a callback.
    # As a device can be disconnected and/or reconnected in a different
    # USB port (giving it a new path), the wallet must be dynamic in
    # asking for its client.
    # If a wallet is successfully paired with a given device, the plugin
    # stores its serial number in the wallet so it can be automatically
    # re-paired if the same device is connected elsewhere.
    # Approaching things this way permits several devices to be connected
    # simultaneously and handled smoothly.

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.wallet_class.device
        self.wallet_class.plugin = self
        self.prevent_timeout = time.time() + 3600 * 24 * 365
        # A set of client instances to USB paths
        self.clients = set()
        # The device wallets we have seen to inform on reconnection
        self.paired_wallets = set()
        self.last_scan = 0

    def thread_jobs(self):
        # Scan connected devices every second.  The test for libraries
        # available is necessary to recover wallets on machines without
        # libraries
        return [self] if self.libraries_available else []

    def run(self):
        now = time.time()
        if now > self.last_scan + 1:
            self.last_scan = now
            self.scan_devices()

            for wallet in self.paired_wallets:
                if now > wallet.last_operation + wallet.session_timeout:
                    client = self.lookup_client(wallet)
                    if client:
                        wallet.last_operation = self.prevent_timeout
                        self.clear_session(client)
                        wallet.timeout()

    def scan_devices(self):
        paths = self.HidTransport.enumerate()
        connected = set([c for c in self.clients if c.path in paths])
        disconnected = self.clients - connected

        self.clients = connected

        # Inform clients and wallets they were disconnected
        for client in disconnected:
            self.print_error("device disconnected:", client)
            if client.wallet:
                client.wallet.disconnected()

        for path in paths:
            # Look for new paths
            if any(c.path == path for c in connected):
                continue

            try:
                transport = self.HidTransport(path)
            except BaseException as e:
                # We were probably just disconnected; never mind
                self.print_error("cannot connect at", path, str(e))
                continue

            self.print_error("connected to device at", path[0])

            try:
                client = self.client_class(transport, path, self)
            except BaseException as e:
                self.print_error("cannot create client for", path, str(e))
            else:
                self.clients.add(client)
                self.print_error("new device:", client)

            # Inform reconnected wallets
            for wallet in self.paired_wallets:
                if wallet.device_id == client.features.device_id:
                    client.wallet = wallet
                    wallet.connected()

    def clear_session(self, client):
        # Clearing the session forces pin re-entry
        self.print_error("clear session:", client)
        client.clear_session()

    def initialize_device(self, wallet, wizard):
        # Prevent timeouts during initialization
        wallet.last_operation = self.prevent_timeout

        (strength, label, pin_protection, passphrase_protection) \
            = wizard.request_trezor_reset_settings(self.device)

        assert strength in range(0, 3)
        strength = 64 * (strength + 2)    # 128, 192 or 256
        language = ''

        client = self.client(wallet)
        client.reset_device(True, strength, passphrase_protection,
                            pin_protection, label, language)


    def select_device(self, wallet, wizard):
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.'''
        clients = list(self.clients)
        suffixes = [_("An unnamed device (wiped)"), _(" (initialized)")]
        labels = [client.label() + suffixes[client.is_initialized()]
                  for client in clients]
        msg = _("Please select which %s device to use:") % self.device
        client = clients[wizard.query_choice(msg, labels)]
        self.pair_wallet(wallet, client)
        if not client.is_initialized():
            self.initialize_device(wallet, wizard)

    def operated_on(self, wallet):
        self.print_error("set last_operation")
        wallet.last_operation = time.time()

    def pair_wallet(self, wallet, client):
        self.print_error("pairing wallet %s to device %s" % (wallet, client))
        self.operated_on(wallet)
        self.paired_wallets.add(wallet)
        wallet.device_id = client.features.device_id
        wallet.last_operation = time.time()
        client.wallet = wallet
        wallet.connected()

    def try_to_pair_wallet(self, wallet):
        '''Call this when loading an existing wallet to find if the
        associated device is connected.'''
        account = '0'
        if not account in wallet.accounts:
            self.print_error("try pair_wallet: wallet has no accounts")
            return None

        first_address = wallet.accounts[account].first_address()[0]
        derivation = wallet.address_derivation(account, 0, 0)
        for client in self.clients:
            if client.wallet:
                continue

            if not client.atleast_version(*self.minimum_firmware):
                wallet.handler.show_error(
                    _('Outdated %s firmware for device labelled %s. Please '
                      'download the updated firmware from %s') %
                    (self.device, client.label(), self.firmware_URL))
                continue

            # This gives us a handler
            client.wallet = wallet
            device_address = None
            try:
                device_address = client.address_from_derivation(derivation)
            finally:
                client.wallet = None

            if first_address == device_address:
                self.pair_wallet(wallet, client)
                return client

        return None

    def lookup_client(self, wallet):
        for client in self.clients:
            if client.features.device_id == wallet.device_id:
                return client
        return None

    def client(self, wallet):
        '''Returns a wrapped client which handles cleanup in case of
        thrown exceptions, etc.'''
        assert isinstance(wallet, self.wallet_class)
        assert wallet.handler != None

        self.operated_on(wallet)
        if wallet.device_id is None:
            client = self.try_to_pair_wallet(wallet)
        else:
            client = self.lookup_client(wallet)

        if not client:
            msg = (_('Could not connect to your %s.  Verify the '
                     'cable is connected and that no other app is '
                     'using it.\nContinuing in watching-only mode '
                     'until the device is re-connected.') % self.device)
            if not self.clients:
                wallet.handler.show_error(msg)
            raise DeviceDisconnectedError(msg)

        return client

    def is_enabled(self):
        return self.libraries_available

    def on_restore_wallet(self, wallet, wizard):
        assert isinstance(wallet, self.wallet_class)

        msg = _("Enter the seed for your %s wallet:" % self.device)
        seed = wizard.request_seed(msg, is_valid = self.is_valid_seed)

        # Restored wallets are not hardware wallets
        wallet_class = self.wallet_class.restore_wallet_class
        wallet.storage.put('wallet_type', wallet_class.wallet_type)
        wallet = wallet_class(wallet.storage)

        passphrase = wizard.request_passphrase(self.device, restore=True)
        password = wizard.request_password()
        wallet.add_seed(seed, password)
        wallet.add_cosigner_seed(seed, 'x/', password, passphrase)
        wallet.create_main_account(password)
        return wallet

    @hook
    def close_wallet(self, wallet):
        if isinstance(wallet, self.wallet_class):
            # Don't retain references to a closed wallet
            self.paired_wallets.discard(wallet)
            client = self.lookup_client(wallet)
            if client:
                self.clear_session(client)
                # Release the device
                self.clients.discard(client)
                client.transport.close()

    def sign_transaction(self, wallet, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.client(wallet)
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(wallet, tx)
        signed_tx = client.sign_tx('Bitcoin', inputs, outputs)[1]
        raw = signed_tx.encode('hex')
        tx.update_signatures(raw)

    def show_address(self, wallet, address):
        client = self.client(wallet)
        if not client.atleast_version(1, 3):
            wallet.handler.show_error(_("Your device firmware is too old"))
            return
        address_path = wallet.address_id(address)
        address_n = client.expand_path(address_path)
        client.get_address('Bitcoin', address_n, True)

    def tx_inputs(self, tx, for_sig=False):
        inputs = []
        for txin in tx.inputs:
            txinputtype = self.types.TxInputType()
            if txin.get('is_coinbase'):
                prev_hash = "\0"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                        txinputtype.address_n.extend(xpub_n + s)
                    else:
                        def f(x_pubkey):
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                            else:
                                xpub = xpub_from_pubkey(x_pubkey.decode('hex'))
                                s = []
                            node = ckd_public.deserialize(xpub)
                            return self.types.HDNodePathType(node=node, address_n=s)
                        pubkeys = map(f, x_pubkeys)
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=map(lambda x: x.decode('hex') if x else '', txin.get('signatures')),
                            m=txin.get('num_sig'),
                        )
                        txinputtype = self.types.TxInputType(
                            script_type=self.types.SPENDMULTISIG,
                            multisig=multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                                    txinputtype.address_n.extend(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if 'scriptSig' in txin:
                script_sig = txin['scriptSig'].decode('hex')
                txinputtype.script_sig = script_sig

            if 'sequence' in txin:
                sequence = txin['sequence']
                txinputtype.sequence = sequence

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, wallet, tx):
        outputs = []

        for type, address, amount in tx.outputs:
            assert type == 'address'
            txoutputtype = self.types.TxOutputType()
            if wallet.is_change(address):
                address_path = wallet.address_id(address)
                address_n = self.client_class.expand_path(address_path)
                txoutputtype.address_n.extend(address_n)
            else:
                txoutputtype.address = address
            txoutputtype.amount = amount
            addrtype, hash_160 = bc_address_to_hash_160(address)
            if addrtype == 0:
                txoutputtype.script_type = self.types.PAYTOADDRESS
            elif addrtype == 5:
                txoutputtype.script_type = self.types.PAYTOSCRIPTHASH
            else:
                raise BaseException('addrtype')
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = self.types.TransactionType()
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']
        inputs = self.tx_inputs(tx)
        t.inputs.extend(inputs)
        for vout in d['outputs']:
            o = t.bin_outputs.add()
            o.amount = vout['value']
            o.script_pubkey = vout['scriptPubKey'].decode('hex')
        return t

    # This function is called from the trezor libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        tx.deserialize()
        return self.electrum_tx_to_txtype(tx)

    @staticmethod
    def is_valid_seed(seed):
        return True
