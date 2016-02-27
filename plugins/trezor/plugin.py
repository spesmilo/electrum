import base64
import re
import threading

from binascii import unhexlify
from functools import partial

from electrum.account import BIP32_Account
from electrum.bitcoin import (bc_address_to_hash_160, xpub_from_pubkey,
                              public_key_to_bc_address, EncodeBase58Check,
                              TYPE_ADDRESS)
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import (deserialize, is_extended_pubkey,
                                  Transaction, x_to_xpub)
from ..hw_wallet import BIP44_HW_Wallet, HW_PluginBase


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)

class TrezorCompatibleWallet(BIP44_HW_Wallet):

    def get_public_key(self, bip32_path):
        client = self.get_client()
        address_n = client.expand_path(bip32_path)
        creating = self.next_account_number() == 0
        node = client.get_public_node(address_n, creating).node
        xpub = ("0488B21E".decode('hex') + chr(node.depth)
                + self.i4b(node.fingerprint) + self.i4b(node.child_num)
                + node.chain_code + node.public_key)
        return EncodeBase58Check(xpub)

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Electrum and %s encryption and decryption are currently incompatible') % self.device)
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

    def get_input_tx(self, tx_hash):
        # First look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        tx = self.transactions.get(tx_hash)
        if not tx:
            request = ('blockchain.transaction.get', [tx_hash])
            # FIXME: what if offline?
            tx = Transaction(self.network.synchronous_get(request))
        return tx

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # previous transactions used as inputs
        prev_tx = {}
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs():
            tx_hash = txin['prevout_hash']
            prev_tx[tx_hash] = self.get_input_tx(tx_hash)
            for x_pubkey in txin['x_pubkeys']:
                if not is_extended_pubkey(x_pubkey):
                    continue
                xpub = x_to_xpub(x_pubkey)
                for k, v in self.master_public_keys.items():
                    if v == xpub:
                        acc_id = re.match("x/(\d+)'", k).group(1)
                        xpub_path[xpub] = self.account_derivation(acc_id)

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)


class TrezorCompatiblePlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        self.main_thread = threading.current_thread()
        # FIXME: move to base class when Ledger is fixed
        if self.libraries_available:
            self.device_manager().register_devices(self.DEVICE_IDS)

    def create_client(self, device, handler):
        if device.interface_number == 1:
            pair = [None, device.path]
        else:
            pair = [device.path, None]

        try:
            transport = self.HidTransport(pair)
        except BaseException as e:
            # We were probably just disconnected; never mind
            self.print_error("cannot connect at", device.path, str(e))
            return None
        self.print_error("connected to device at", device.path)

        client = self.client_class(transport, handler, self)

        # Try a ping for device sanity
        try:
            client.ping('t')
        except BaseException as e:
            self.print_error("ping failed", str(e))
            return None

        if not client.atleast_version(*self.minimum_firmware):
            msg = (_('Outdated %s firmware for device labelled %s. Please '
                     'download the updated firmware from %s') %
                   (self.device, client.label(), self.firmware_URL))
            handler.show_error(msg)
            return None

        return client

    def get_client(self, wallet, force_pair=True):
        # All client interaction should not be in the main GUI thread
        assert self.main_thread != threading.current_thread()

        devmgr = self.device_manager()
        client = devmgr.client_for_wallet(self, wallet, force_pair)
        if client:
            client.used()

        return client

    def initialize_device(self, wallet):
        # Initialization method
        msg = _("Choose how you want to initialize your %s.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer.\n\n"
                "For the last two methods you input secrets on your keyboard "
                "and upload them to your %s, and so you should "
                "only do those on a computer you know to be trustworthy "
                "and free of malware."
        ) % (self.device, self.device)

        methods = [
            # Must be short as QT doesn't word-wrap radio button text
            _("Let the device generate a completely new seed randomly"),
            _("Recover from a seed you have previously written down"),
            _("Upload a BIP39 mnemonic to generate the seed"),
            _("Upload a master private key")
        ]

        method = wallet.handler.query_choice(msg, methods)
        (item, label, pin_protection, passphrase_protection) \
            = wallet.handler.request_trezor_init_settings(method, self.device)

        if method == TIM_RECOVER and self.device == 'TREZOR':
            # Warn user about firmware lameness
            wallet.handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"))

        language = 'english'

        def initialize_method():
            client = self.get_client(wallet)

            if method == TIM_NEW:
                strength = 64 * (item + 2)  # 128, 192 or 256
                client.reset_device(True, strength, passphrase_protection,
                                    pin_protection, label, language)
            elif method == TIM_RECOVER:
                word_count = 6 * (item + 2)  # 12, 18 or 24
                client.step = 0
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
            # After successful initialization create accounts
            wallet.create_hd_account(None)

        return initialize_method

    def setup_device(self, wallet, on_done, on_error):
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.  Then create the wallet accounts.'''
        devmgr = self.device_manager()
        device_info = devmgr.select_device(wallet, self)
        devmgr.pair_wallet(wallet, device_info.device.id_)
        if device_info.initialized:
            task = partial(wallet.create_hd_account, None)
        else:
            task = self.initialize_device(wallet)
        wallet.thread.add(task, on_done=on_done, on_error=on_error)

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
        for txin in tx.inputs():
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
                            node = self.ckd_public.deserialize(xpub)
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
        for type, address, amount in tx.outputs():
            assert type == TYPE_ADDRESS
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
        return self.electrum_tx_to_txtype(tx)

    @staticmethod
    def is_valid_seed(seed):
        return True
