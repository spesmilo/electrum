import threading

from binascii import hexlify, unhexlify

from electrum.util import bfh, bh2u, versiontuple
from electrum.bitcoin import (b58_address_to_hash160, xpub_from_pubkey,
                              TYPE_ADDRESS, TYPE_SCRIPT, NetworkConstants)
from electrum.i18n import _
from electrum.plugins import BasePlugin, Device
from electrum.transaction import deserialize
from electrum.keystore import Hardware_KeyStore, is_xpubkey, parse_xpubkey

from ..hw_wallet import HW_PluginBase


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)

# script "generation"
SCRIPT_GEN_LEGACY, SCRIPT_GEN_P2SH_SEGWIT, SCRIPT_GEN_NATIVE_SEGWIT = range(0, 3)


class TrezorKeyStore(Hardware_KeyStore):
    hw_type = 'trezor'
    device = 'TREZOR'

    def get_derivation(self):
        return self.derivation

    def get_script_gen(self):
        def is_p2sh_segwit():
            return self.derivation.startswith("m/49'/")

        def is_native_segwit():
            return self.derivation.startswith("m/84'/")

        if is_native_segwit():
            return SCRIPT_GEN_NATIVE_SEGWIT
        elif is_p2sh_segwit():
            return SCRIPT_GEN_P2SH_SEGWIT
        else:
            return SCRIPT_GEN_LEGACY

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def decrypt_message(self, sequence, message, password):
        raise RuntimeError(_('Encryption and decryption are not implemented by {}').format(self.device))

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
            prev_tx[tx_hash] = txin['prev_tx']
            for x_pubkey in x_pubkeys:
                if not is_xpubkey(x_pubkey):
                    continue
                xpub, s = parse_xpubkey(x_pubkey)
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)


class TrezorPlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types

    firmware_URL = 'https://wallet.trezor.io'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    minimum_firmware = (1, 5, 2)
    keystore_class = TrezorKeyStore
    minimum_library = (0, 9, 0)

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        self.main_thread = threading.current_thread()

        try:
            # Minimal test if python-trezor is installed
            import trezorlib
            try:
                library_version = trezorlib.__version__
            except AttributeError:
                # python-trezor only introduced __version__ in 0.9.0
                library_version = 'unknown'
            if library_version == 'unknown' or \
                    versiontuple(library_version) < self.minimum_library:
                self.libraries_available_message = (
                        _("Library version for '{}' is too old.").format(name)
                        + '\nInstalled: {}, Needed: {}'
                        .format(library_version, self.minimum_library))
                self.print_stderr(self.libraries_available_message)
                raise ImportError()
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False
            return

        from . import client
        import trezorlib.ckd_public
        import trezorlib.messages
        self.client_class = client.TrezorClient
        self.ckd_public = trezorlib.ckd_public
        self.types = trezorlib.messages
        self.DEVICE_IDS = ('TREZOR',)

        self.device_manager().register_enumerate_func(self.enumerate)

    def enumerate(self):
        from trezorlib.device import TrezorDevice
        return [Device(d.get_path(), -1, d.get_path(), 'TREZOR', 0) for d in TrezorDevice.enumerate()]

    def create_client(self, device, handler):
        from trezorlib.device import TrezorDevice
        try:
            self.print_error("connecting to device at", device.path)
            transport = TrezorDevice.find_by_path(device.path)
        except BaseException as e:
            self.print_error("cannot connect at", device.path, str(e))
            return None

        if not transport:
            self.print_error("cannot connect at", device.path)
            return

        self.print_error("connected to device at", device.path)
        client = self.client_class(transport, handler, self)

        # Try a ping for device sanity
        try:
            client.ping('t')
        except BaseException as e:
            self.print_error("ping failed", str(e))
            return None

        if not client.atleast_version(*self.minimum_firmware):
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                   .format(self.device, client.label(), self.firmware_URL))
            self.print_error(msg)
            handler.show_error(msg)
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
        return "Testnet" if NetworkConstants.TESTNET else "Bitcoin"

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
            t = threading.Thread(target = self._initialize_device, args=(settings, method, device_id, wizard, handler))
            t.setDaemon(True)
            t.start()
            wizard.loop.exec_()
        wizard.choice_dialog(title=_('Initialize Device'), message=msg, choices=choices, run_next=f)

    def _initialize_device(self, settings, method, device_id, wizard, handler):
        item, label, pin_protection, passphrase_protection = settings

        if method == TIM_RECOVER:
            # FIXME the PIN prompt will appear over this message
            # which makes this unreadable
            handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"))

        language = 'english'
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)

        if method == TIM_NEW:
            strength = 64 * (item + 2)  # 128, 192 or 256
            u2f_counter = 0
            skip_backup = False
            client.reset_device(True, strength, passphrase_protection,
                                pin_protection, label, language,
                                u2f_counter, skip_backup)
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
        wizard.loop.exit(0)

    def setup_device(self, device_info, wizard, purpose):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        # fixme: we should use: client.handler = wizard
        client.handler = self.create_handler(wizard)
        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_xpub('m', 'standard')
        client.used()

    def get_xpub(self, device_id, derivation, xtype, wizard):
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = wizard
        xpub = client.get_xpub(derivation, xtype)
        client.used()
        return xpub

    def sign_transaction(self, keystore, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, True, keystore.get_script_gen())
        outputs = self.tx_outputs(keystore.get_derivation(), tx, keystore.get_script_gen())
        signed_tx = client.sign_tx(self.get_coin_name(), inputs, outputs, lock_time=tx.locktime)[1]
        raw = bh2u(signed_tx)
        tx.update_signatures(raw)

    def show_address(self, wallet, keystore, address):
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
            script_gen = keystore.get_script_gen()
            if script_gen == SCRIPT_GEN_NATIVE_SEGWIT:
                script_type = self.types.InputScriptType.SPENDWITNESS
            elif script_gen == SCRIPT_GEN_P2SH_SEGWIT:
                script_type = self.types.InputScriptType.SPENDP2SHWITNESS
            else:
                script_type = self.types.InputScriptType.SPENDADDRESS
            client.get_address(self.get_coin_name(), address_n, True, script_type=script_type)
        else:
            def f(xpub):
                node = self.ckd_public.deserialize(xpub)
                return self.types.HDNodePathType(node=node, address_n=[change, index])
            pubkeys = wallet.get_public_keys(address)
            # sort xpubs using the order of pubkeys
            sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
            pubkeys = list(map(f, sorted_xpubs))
            multisig = self.types.MultisigRedeemScriptType(
               pubkeys=pubkeys,
               signatures=[b''] * wallet.n,
               m=wallet.m,
            )
            client.get_address(self.get_coin_name(), address_n, True, multisig=multisig)

    def tx_inputs(self, tx, for_sig=False, script_gen=SCRIPT_GEN_LEGACY):
        inputs = []
        for txin in tx.inputs():
            txinputtype = self.types.TxInputType()
            if txin['type'] == 'coinbase':
                prev_hash = "\0"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                        txinputtype._extend_address_n(xpub_n + s)
                        if script_gen == SCRIPT_GEN_NATIVE_SEGWIT:
                            txinputtype.script_type = self.types.InputScriptType.SPENDWITNESS
                        elif script_gen == SCRIPT_GEN_P2SH_SEGWIT:
                            txinputtype.script_type = self.types.InputScriptType.SPENDP2SHWITNESS
                        else:
                            txinputtype.script_type = self.types.InputScriptType.SPENDADDRESS
                    else:
                        def f(x_pubkey):
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
                            else:
                                xpub = xpub_from_pubkey(0, bfh(x_pubkey))
                                s = []
                            node = self.ckd_public.deserialize(xpub)
                            return self.types.HDNodePathType(node=node, address_n=s)
                        pubkeys = list(map(f, x_pubkeys))
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=list(map(lambda x: bfh(x)[:-1] if x else b'', txin.get('signatures'))),
                            m=txin.get('num_sig'),
                        )
                        if script_gen == SCRIPT_GEN_NATIVE_SEGWIT:
                            script_type = self.types.InputScriptType.SPENDWITNESS
                        elif script_gen == SCRIPT_GEN_P2SH_SEGWIT:
                            script_type = self.types.InputScriptType.SPENDP2SHWITNESS
                        else:
                            script_type = self.types.InputScriptType.SPENDMULTISIG
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
                                    txinputtype._extend_address_n(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            if 'value' in txin:
                txinputtype.amount = txin['value']
            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if 'scriptSig' in txin:
                script_sig = bfh(txin['scriptSig'])
                txinputtype.script_sig = script_sig

            txinputtype.sequence = txin.get('sequence', 0xffffffff - 1)

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, derivation, tx, script_gen=SCRIPT_GEN_LEGACY):
        outputs = []
        has_change = False

        for _type, address, amount in tx.outputs():
            info = tx.output_info.get(address)
            if info is not None and not has_change:
                has_change = True # no more than one change address
                index, xpubs, m = info
                if len(xpubs) == 1:
                    if script_gen == SCRIPT_GEN_NATIVE_SEGWIT:
                        script_type = self.types.OutputScriptType.PAYTOWITNESS
                    elif script_gen == SCRIPT_GEN_P2SH_SEGWIT:
                        script_type = self.types.OutputScriptType.PAYTOP2SHWITNESS
                    else:
                        script_type = self.types.OutputScriptType.PAYTOADDRESS
                    address_n = self.client_class.expand_path(derivation + "/%d/%d"%index)
                    txoutputtype = self.types.TxOutputType(
                        amount = amount,
                        script_type = script_type,
                        address_n = address_n,
                    )
                else:
                    if script_gen == SCRIPT_GEN_NATIVE_SEGWIT:
                        script_type = self.types.OutputScriptType.PAYTOWITNESS
                    elif script_gen == SCRIPT_GEN_P2SH_SEGWIT:
                        script_type = self.types.OutputScriptType.PAYTOP2SHWITNESS
                    else:
                        script_type = self.types.OutputScriptType.PAYTOMULTISIG
                    address_n = self.client_class.expand_path("/%d/%d"%index)
                    nodes = map(self.ckd_public.deserialize, xpubs)
                    pubkeys = [ self.types.HDNodePathType(node=node, address_n=address_n) for node in nodes]
                    multisig = self.types.MultisigRedeemScriptType(
                        pubkeys = pubkeys,
                        signatures = [b''] * len(pubkeys),
                        m = m)
                    txoutputtype = self.types.TxOutputType(
                        multisig = multisig,
                        amount = amount,
                        address_n = self.client_class.expand_path(derivation + "/%d/%d"%index),
                        script_type = script_type)
            else:
                txoutputtype = self.types.TxOutputType()
                txoutputtype.amount = amount
                if _type == TYPE_SCRIPT:
                    txoutputtype.script_type = self.types.OutputScriptType.PAYTOOPRETURN
                    txoutputtype.op_return_data = address[2:]
                elif _type == TYPE_ADDRESS:
                    txoutputtype.script_type = self.types.OutputScriptType.PAYTOADDRESS
                    txoutputtype.address = address

            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = self.types.TransactionType()
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']
        inputs = self.tx_inputs(tx)
        t._extend_inputs(inputs)
        for vout in d['outputs']:
            o = t._add_bin_outputs()
            o.amount = vout['value']
            o.script_pubkey = bfh(vout['scriptPubKey'])
        return t

    # This function is called from the trezor libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        return self.electrum_tx_to_txtype(tx)
