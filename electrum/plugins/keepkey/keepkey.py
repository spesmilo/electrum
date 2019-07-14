from binascii import hexlify, unhexlify
import traceback
import sys

from electrum.util import bfh, bh2u, UserCancelled, UserFacingException
from electrum.bitcoin import TYPE_ADDRESS, TYPE_SCRIPT
from electrum.bip32 import BIP32Node
from electrum import constants
from electrum.i18n import _
from electrum.transaction import deserialize, Transaction
from electrum.keystore import Hardware_KeyStore, is_xpubkey, parse_xpubkey
from electrum.base_wizard import ScriptTypeNotSupported

from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch, trezor_validate_op_return_output_and_get_data


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)


class KeepKey_KeyStore(Hardware_KeyStore):
    hw_type = 'keepkey'
    device = 'KeepKey'

    def get_derivation(self):
        return self.derivation

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def decrypt_message(self, sequence, message, password):
        raise UserFacingException(_('Encryption and decryption are not implemented by {}').format(self.device))

    def sign_message(self, sequence, message, password):
        client = self.get_client()
        address_path = self.get_derivation() + "/%d/%d"%sequence
        address_n = client.expand_path(address_path)
        msg_sig = client.sign_message(self.plugin.get_coin_name(), address_n, message)
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # previous transactions used as inputs
        prev_tx = {}
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs():
            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            tx_hash = txin['prevout_hash']
            if txin.get('prev_tx') is None and not Transaction.is_segwit_input(txin):
                raise UserFacingException(_('Offline signing with {} is not supported for legacy inputs.').format(self.device))
            prev_tx[tx_hash] = txin['prev_tx']
            for x_pubkey in x_pubkeys:
                if not is_xpubkey(x_pubkey):
                    continue
                xpub, s = parse_xpubkey(x_pubkey)
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)


class KeepKeyPlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    firmware_URL = 'https://www.keepkey.com'
    libraries_URL = 'https://github.com/keepkey/python-keepkey'
    minimum_firmware = (1, 0, 0)
    keystore_class = KeepKey_KeyStore
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        try:
            from . import client
            import keepkeylib
            import keepkeylib.ckd_public
            import keepkeylib.transport_hid
            import keepkeylib.transport_webusb
            self.client_class = client.KeepKeyClient
            self.ckd_public = keepkeylib.ckd_public
            self.types = keepkeylib.client.types
            self.DEVICE_IDS = (keepkeylib.transport_hid.DEVICE_IDS +
                               keepkeylib.transport_webusb.DEVICE_IDS)
            self.device_manager().register_devices(self.DEVICE_IDS)
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False

    def hid_transport(self, pair):
        from keepkeylib.transport_hid import HidTransport
        return HidTransport(pair)

    def webusb_transport(self, device):
        from keepkeylib.transport_webusb import WebUsbTransport
        for d in WebUsbTransport.enumerate():
            if device.id_.startswith(d.getSerialNumber()):
                return WebUsbTransport(d)
        return WebUsbTransport(device)

    def _try_hid(self, device):
        self.logger.info("Trying to connect over USB...")
        if device.interface_number == 1:
            pair = [None, device.path]
        else:
            pair = [device.path, None]

        try:
            return self.hid_transport(pair)
        except BaseException as e:
            # see fdb810ba622dc7dbe1259cbafb5b28e19d2ab114
            # raise
            self.logger.info(f"cannot connect at {device.path} {e}")
            return None

    def _try_webusb(self, device):
        self.logger.info("Trying to connect over WebUSB...")
        try:
            return self.webusb_transport(device)
        except BaseException as e:
            self.logger.info(f"cannot connect at {device.path} {e}")
            return None

    def create_client(self, device, handler):
        if device.product_key[1] == 2:
            transport = self._try_webusb(device)
        else:
            transport = self._try_hid(device)

        if not transport:
            self.logger.info("cannot connect to device")
            return

        self.logger.info(f"connected to device at {device.path}")

        client = self.client_class(transport, handler, self)

        # Try a ping for device sanity
        try:
            client.ping('t')
        except BaseException as e:
            self.logger.info(f"ping failed {e}")
            return None

        if not client.atleast_version(*self.minimum_firmware):
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                   .format(self.device, client.label(), self.firmware_URL))
            self.logger.info(msg)
            if handler:
                handler.show_error(msg)
            else:
                raise UserFacingException(msg)
            return None

        return client

    def get_client(self, keystore, force_pair=True):
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def get_coin_name(self):
        return "Testnet" if constants.net.TESTNET else "Bitcoin"

    def initialize_device(self, device_id, wizard, handler):
        # Initialization method
        msg = _("Choose how you want to initialize your {}.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer.\n\n"
                "For the last two methods you input secrets on your keyboard "
                "and upload them to your {}, and so you should "
                "only do those on a computer you know to be trustworthy "
                "and free of malware."
        ).format(self.device, self.device)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            (TIM_NEW, _("Let the device generate a completely new seed randomly")),
            (TIM_RECOVER, _("Recover from a seed you have previously written down")),
            (TIM_MNEMONIC, _("Upload a BIP39 mnemonic to generate the seed")),
            (TIM_PRIVKEY, _("Upload a master private key"))
        ]
        def f(method):
            import threading
            settings = self.request_trezor_init_settings(wizard, method, self.device)
            t = threading.Thread(target=self._initialize_device_safe, args=(settings, method, device_id, wizard, handler))
            t.setDaemon(True)
            t.start()
            exit_code = wizard.loop.exec_()
            if exit_code != 0:
                # this method (initialize_device) was called with the expectation
                # of leaving the device in an initialized state when finishing.
                # signal that this is not the case:
                raise UserCancelled()
        wizard.choice_dialog(title=_('Initialize Device'), message=msg, choices=choices, run_next=f)

    def _initialize_device_safe(self, settings, method, device_id, wizard, handler):
        exit_code = 0
        try:
            self._initialize_device(settings, method, device_id, wizard, handler)
        except UserCancelled:
            exit_code = 1
        except BaseException as e:
            self.logger.exception('')
            handler.show_error(str(e))
            exit_code = 1
        finally:
            wizard.loop.exit(exit_code)

    def _initialize_device(self, settings, method, device_id, wizard, handler):
        item, label, pin_protection, passphrase_protection = settings

        language = 'english'
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

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

    def _make_node_path(self, xpub, address_n):
        bip32node = BIP32Node.from_xkey(xpub)
        node = self.types.HDNodeType(
            depth=bip32node.depth,
            fingerprint=int.from_bytes(bip32node.fingerprint, 'big'),
            child_num=int.from_bytes(bip32node.child_number, 'big'),
            chain_code=bip32node.chaincode,
            public_key=bip32node.eckey.get_public_key_bytes(compressed=True),
        )
        return self.types.HDNodePathType(node=node, address_n=address_n)

    def setup_device(self, device_info, wizard, purpose):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise UserFacingException(_('Failed to create a client for this device.') + '\n' +
                                      _('Make sure it is in the correct state.'))
        # fixme: we should use: client.handler = wizard
        client.handler = self.create_handler(wizard)
        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_xpub('m', 'standard')
        client.used()

    def get_xpub(self, device_id, derivation, xtype, wizard):
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script is not supported with {}.').format(self.device))
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = wizard
        xpub = client.get_xpub(derivation, xtype)
        client.used()
        return xpub

    def get_keepkey_input_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.SPENDWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.SPENDP2SHWITNESS
        if electrum_txin_type in ('p2pkh', ):
            return self.types.SPENDADDRESS
        if electrum_txin_type in ('p2sh', ):
            return self.types.SPENDMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def get_keepkey_output_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.PAYTOWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.PAYTOP2SHWITNESS
        if electrum_txin_type in ('p2pkh', ):
            return self.types.PAYTOADDRESS
        if electrum_txin_type in ('p2sh', ):
            return self.types.PAYTOMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def sign_transaction(self, keystore, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(keystore.get_derivation(), tx)
        signatures = client.sign_tx(self.get_coin_name(), inputs, outputs,
                                    lock_time=tx.locktime, version=tx.version)[0]
        signatures = [(bh2u(x) + '01') for x in signatures]
        tx.update_signatures(signatures)

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        client = self.get_client(keystore)
        if not client.atleast_version(1, 3):
            keystore.handler.show_error(_("Your device firmware is too old"))
            return
        change, index = wallet.get_address_index(address)
        derivation = keystore.derivation
        address_path = "%s/%d/%d"%(derivation, change, index)
        address_n = client.expand_path(address_path)
        xpubs = wallet.get_master_public_keys()
        if len(xpubs) == 1:
            script_type = self.get_keepkey_input_script_type(wallet.txin_type)
            client.get_address(self.get_coin_name(), address_n, True, script_type=script_type)
        else:
            def f(xpub):
                return self._make_node_path(xpub, [change, index])
            pubkeys = wallet.get_public_keys(address)
            # sort xpubs using the order of pubkeys
            sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
            pubkeys = list(map(f, sorted_xpubs))
            multisig = self.types.MultisigRedeemScriptType(
               pubkeys=pubkeys,
               signatures=[b''] * wallet.n,
               m=wallet.m,
            )
            script_type = self.get_keepkey_input_script_type(wallet.txin_type)
            client.get_address(self.get_coin_name(), address_n, True, multisig=multisig, script_type=script_type)

    def tx_inputs(self, tx, for_sig=False):
        inputs = []
        for txin in tx.inputs():
            txinputtype = self.types.TxInputType()
            if txin['type'] == 'coinbase':
                prev_hash = b"\x00"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                        txinputtype.address_n.extend(xpub_n + s)
                        txinputtype.script_type = self.get_keepkey_input_script_type(txin['type'])
                    else:
                        def f(x_pubkey):
                            xpub, s = parse_xpubkey(x_pubkey)
                            return self._make_node_path(xpub, s)
                        pubkeys = list(map(f, x_pubkeys))
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=map(lambda x: bfh(x)[:-1] if x else b'', txin.get('signatures')),
                            m=txin.get('num_sig'),
                        )
                        script_type = self.get_keepkey_input_script_type(txin['type'])
                        txinputtype = self.types.TxInputType(
                            script_type=script_type,
                            multisig=multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                                    txinputtype.address_n.extend(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            if 'value' in txin:
                txinputtype.amount = txin['value']
            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if txin.get('scriptSig') is not None:
                script_sig = bfh(txin['scriptSig'])
                txinputtype.script_sig = script_sig

            txinputtype.sequence = txin.get('sequence', 0xffffffff - 1)

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, derivation, tx):

        def create_output_by_derivation():
            script_type = self.get_keepkey_output_script_type(info.script_type)
            if len(xpubs) == 1:
                address_n = self.client_class.expand_path(derivation + "/%d/%d" % index)
                txoutputtype = self.types.TxOutputType(
                    amount=amount,
                    script_type=script_type,
                    address_n=address_n,
                )
            else:
                address_n = self.client_class.expand_path("/%d/%d" % index)
                pubkeys = [self._make_node_path(xpub, address_n) for xpub in xpubs]
                multisig = self.types.MultisigRedeemScriptType(
                    pubkeys=pubkeys,
                    signatures=[b''] * len(pubkeys),
                    m=m)
                txoutputtype = self.types.TxOutputType(
                    multisig=multisig,
                    amount=amount,
                    address_n=self.client_class.expand_path(derivation + "/%d/%d" % index),
                    script_type=script_type)
            return txoutputtype

        def create_output_by_address():
            txoutputtype = self.types.TxOutputType()
            txoutputtype.amount = amount
            if _type == TYPE_SCRIPT:
                txoutputtype.script_type = self.types.PAYTOOPRETURN
                txoutputtype.op_return_data = trezor_validate_op_return_output_and_get_data(o)
            elif _type == TYPE_ADDRESS:
                txoutputtype.script_type = self.types.PAYTOADDRESS
                txoutputtype.address = address
            return txoutputtype

        outputs = []
        has_change = False
        any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)

        for o in tx.outputs():
            _type, address, amount = o.type, o.address, o.value
            use_create_by_derivation = False

            info = tx.output_info.get(address)
            if info is not None and not has_change:
                index, xpubs, m = info.address_index, info.sorted_xpubs, info.num_sig
                on_change_branch = index[0] == 1
                # prioritise hiding outputs on the 'change' branch from user
                # because no more than one change address allowed
                if on_change_branch == any_output_on_change_branch:
                    use_create_by_derivation = True
                    has_change = True

            if use_create_by_derivation:
                txoutputtype = create_output_by_derivation()
            else:
                txoutputtype = create_output_by_address()
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = self.types.TransactionType()
        if tx is None:
            # probably for segwit input and we don't need this prev txn
            return t
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']
        inputs = self.tx_inputs(tx)
        t.inputs.extend(inputs)
        for vout in d['outputs']:
            o = t.bin_outputs.add()
            o.amount = vout['value']
            o.script_pubkey = bfh(vout['scriptPubKey'])
        return t

    # This function is called from the TREZOR libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        return self.electrum_tx_to_txtype(tx)
