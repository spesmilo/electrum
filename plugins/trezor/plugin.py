import base64
import re
import time

from binascii import unhexlify
from struct import pack

from electrum.account import BIP32_Account
from electrum.bitcoin import (bc_address_to_hash_160, xpub_from_pubkey,
                              public_key_to_bc_address, EncodeBase58Check)
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import (deserialize, is_extended_pubkey,
                                  Transaction, x_to_xpub)
from electrum.wallet import BIP32_HD_Wallet, BIP44_Wallet
from electrum.util import ThreadJob
from electrum.plugins import DeviceMgr

# Trezor initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)

class DeviceDisconnectedError(Exception):
    pass

class OutdatedFirmwareError(Exception):
    pass

class TrezorCompatibleWallet(BIP44_Wallet):
    # Extend BIP44 Wallet as required by hardware implementation.
    # Derived classes must set:
    #   - device
    #   - DEVICE_IDS
    #   - wallet_type

    restore_wallet_class = BIP44_Wallet

    def __init__(self, storage):
        BIP44_Wallet.__init__(self, storage)
        # After timeout seconds we clear the device session
        self.session_timeout = storage.get('session_timeout', 180)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.handler = None
        self.force_watching_only = True

    def set_session_timeout(self, seconds):
        self.print_error("setting session timeout to %d seconds" % seconds)
        self.session_timeout = seconds
        self.storage.put('session_timeout', seconds)

    def disconnected(self):
        '''A device paired with the wallet was diconnected.  Note this is
        called in the context of the Plugins thread.'''
        self.print_error("disconnected")
        self.force_watching_only = True
        self.handler.watching_only_changed()

    def connected(self):
        '''A device paired with the wallet was (re-)connected.  Note this
        is called in the context of the Plugins thread.'''
        self.print_error("connected")
        self.force_watching_only = False
        self.handler.watching_only_changed()

    def timeout(self):
        '''Informs the wallet it timed out.  Note this is called from
        the Plugins thread.'''
        self.print_error("timed out")

    def get_action(self):
        pass

    def can_create_accounts(self):
        return True

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is watching-only if its trezor device is unpaired.'''
        assert not self.has_seed()
        return self.force_watching_only

    def can_change_password(self):
        return False

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def first_address(self):
        '''Used to check a hardware wallet matches a software wallet'''
        account = self.accounts.get('0')
        derivation = self.address_derivation('0', 0, 0)
        return (account.first_address()[0] if account else None, derivation)

    def derive_xkeys(self, root, derivation, password):
        if self.master_public_keys.get(root):
            return BIP44_wallet.derive_xkeys(self, root, derivation, password)

        # When creating a wallet we need to ask the device for the
        # master public key
        derivation = derivation.replace(self.root_name, self.prefix() + "/")
        xpub = self.get_public_key(derivation)
        return xpub, None

    def get_public_key(self, bip32_path):
        client = self.get_client()
        address_n = client.expand_path(bip32_path)
        node = client.get_public_node(address_n).node
        xpub = ("0488B21E".decode('hex') + chr(node.depth)
                + self.i4b(node.fingerprint) + self.i4b(node.child_num)
                + node.chain_code + node.public_key)
        return EncodeBase58Check(xpub)

    def i4b(self, x):
        return pack('>I', x)

    def decrypt_message(self, pubkey, message, password):
        address = public_key_to_bc_address(pubkey.decode('hex'))
        client = self.get_client()
        address_path = self.address_id(address)
        address_n = client.expand_path(address_path)
        payload = base64.b64decode(message)
        nonce, message, msg_hmac = payload[:33], payload[33:-8], payload[-8:]
        result = client.decrypt_message(address_n, nonce, message, msg_hmac)
        return result.message

    def sign_message(self, address, message, password):
        client = self.get_client()
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

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.wallet_class.device
        self.wallet_class.plugin = self
        self.prevent_timeout = time.time() + 3600 * 24 * 365
        if self.libraries_available:
            self.device_manager().register_devices(
                self.DEVICE_IDS, self.create_client)

    def is_enabled(self):
        return self.libraries_available

    def device_manager(self):
        return self.parent.device_manager

    def thread_jobs(self):
        # Thread job to handle device timeouts
        return [self] if self.libraries_available else []

    def run(self):
        '''Handle device timeouts.  Runs in the context of the Plugins
        thread.'''
        now = time.time()
        for wallet in self.device_manager().paired_wallets():
            if (isinstance(wallet, self.wallet_class)
                    and hasattr(wallet, 'last_operation')
                    and now > wallet.last_operation + wallet.session_timeout):
                client = self.get_client(wallet, force_pair=False)
                if client:
                    client.clear_session()
                    wallet.last_operation = self.prevent_timeout
                    wallet.timeout()

    def create_client(self, path, handler, hid_id):
        pair = ((None, path) if self.HidTransport._detect_debuglink(path)
                else (path, None))
        try:
            transport = self.HidTransport(pair)
        except BaseException as e:
            # We were probably just disconnected; never mind
            self.print_error("cannot connect at", path, str(e))
            return None
        self.print_error("connected to device at", path)
        return self.client_class(transport, handler, self, hid_id)

    def get_client(self, wallet, force_pair=True, check_firmware=True):
        '''check_firmware is ignored unless force_pair is True.'''
        client = self.device_manager().get_client(wallet, force_pair)

        # Try a ping for device sanity
        if client:
            self.print_error("set last_operation")
            wallet.last_operation = time.time()
            try:
                client.ping('t')
            except BaseException as e:
                self.print_error("ping failed", str(e))
                # Remove it from the manager's cache
                self.device_manager().close_client(client)
                client = None

        if force_pair:
            assert wallet.handler
            if not client:
                msg = (_('Could not connect to your %s.  Verify the '
                         'cable is connected and that no other app is '
                         'using it.\nContinuing in watching-only mode '
                         'until the device is re-connected.') % self.device)
                wallet.handler.show_error(msg)
                raise DeviceDisconnectedError(msg)

            if (check_firmware and not
                client.atleast_version(*self.minimum_firmware)):
                msg = (_('Outdated %s firmware for device labelled %s. Please '
                         'download the updated firmware from %s') %
                       (self.device, client.label(), self.firmware_URL))
                wallet.handler.show_error(msg)
                raise OutdatedFirmwareError(msg)

        return client

    @hook
    def close_wallet(self, wallet):
        if isinstance(wallet, self.wallet_class):
            self.device_manager().close_wallet(wallet)

    def initialize_device(self, wallet):
        # Prevent timeouts during initialization
        wallet.last_operation = self.prevent_timeout

        # Initialization method
        msg = _("Please select how you want to initialize your %s.\n"
                "The first two are secure as no secret information is entered "
                "onto your computer.\nFor the last two methods you enter "
                "secrets into your computer and upload them to the device, "
                "and so you should do those on a computer you know to be "
                "trustworthy and free of malware."
        ) % self.device

        methods = [
            _("Let the device generate a completely new seed randomly"),
            _("Recover from an existing %s seed you have previously written "
              "down" % self.device),
            _("Upload a BIP39 mnemonic to generate the seed"),
            _("Upload a master private key")
        ]

        method = wallet.handler.query_choice(msg, methods)
        (item, label, pin_protection, passphrase_protection) \
            = wallet.handler.request_trezor_init_settings(method, self.device)

        client = self.get_client(wallet)
        language = 'english'

        if method == TIM_NEW:
            strength = 64 * (item + 2)  # 128, 192 or 256
            client.reset_device(True, strength, passphrase_protection,
                                pin_protection, label, language)
        elif method == TIM_RECOVER:
            word_count = 6 * (item + 2)  # 12, 18 or 24
            client.recovery_device(word_count, passphrase_protection,
                                   pin_protection, label, language)
        elif method == TIM_MNEMONIC:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_mnemonic(str(item), pin,
                                           passphrase_protection,
                                           label, language)
        else:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_xprv(item, pin, passphrase_protection,
                                       label, language)

    def unpaired_clients(self, handler):
        '''Returns all connected, unpaired devices as a list of clients and a
        list of descriptions.'''
        devmgr = self.device_manager()
        clients = devmgr.unpaired_clients(handler, self.client_class)
        states = [_("wiped"), _("initialized")]
        def client_desc(client):
            label = client.label() or _("An unnamed device")
            state = states[client.is_initialized()]
            return ("%s: serial number %s (%s)"
                    % (label, client.hid_id(), state))
        return clients, list(map(client_desc, clients))

    def select_device(self, wallet):
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.'''
        msg = _("Please select which %s device to use:") % self.device
        clients, labels = self.unpaired_clients(wallet.handler)
        client = clients[wallet.handler.query_choice(msg, labels)]
        self.device_manager().pair_wallet(wallet, client)
        if not client.is_initialized():
            self.initialize_device(wallet)

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
        wallet.create_hd_account(password)
        return wallet

    def sign_transaction(self, wallet, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client(wallet)
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(wallet, tx)
        signed_tx = client.sign_tx('Bitcoin', inputs, outputs)[1]
        raw = signed_tx.encode('hex')
        tx.update_signatures(raw)

    def show_address(self, wallet, address):
        client = self.get_client(wallet)
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
