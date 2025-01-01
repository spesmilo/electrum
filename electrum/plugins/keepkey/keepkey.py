from typing import Optional, TYPE_CHECKING, Sequence

from electrum.util import UserFacingException
from electrum.bip32 import BIP32Node
from electrum import descriptor
from electrum import constants
from electrum.i18n import _
from electrum.transaction import Transaction, PartialTransaction, PartialTxInput, Sighash
from electrum.keystore import Hardware_KeyStore
from electrum.plugin import Device, runs_in_hwd_thread

from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch, trezor_validate_op_return_output_and_get_data

if TYPE_CHECKING:
    import usb1
    from .client import KeepKeyClient
    from electrum.plugin import DeviceInfo
    from electrum.wizard import NewWalletWizard


# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)


class KeepKey_KeyStore(Hardware_KeyStore):
    hw_type = 'keepkey'
    device = 'KeepKey'

    plugin: 'KeepKeyPlugin'

    def decrypt_message(self, sequence, message, password):
        raise UserFacingException(_('Encryption and decryption are not implemented by {}').format(self.device))

    @runs_in_hwd_thread
    def sign_message(self, sequence, message, password, *, script_type=None):
        client = self.get_client()
        address_path = self.get_derivation_prefix() + "/%d/%d"%sequence
        address_n = client.expand_path(address_path)
        msg_sig = client.sign_message(self.plugin.get_coin_name(), address_n, message)
        return msg_sig.signature

    @runs_in_hwd_thread
    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # previous transactions used as inputs
        prev_tx = {}
        for txin in tx.inputs():
            tx_hash = txin.prevout.txid.hex()
            if txin.utxo is None and not txin.is_segwit():
                raise UserFacingException(_('Missing previous tx for legacy input.'))
            prev_tx[tx_hash] = txin.utxo

        self.plugin.sign_transaction(self, tx, prev_tx)


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
            # only "register" hid device id:
            self.device_manager().register_devices(keepkeylib.transport_hid.DEVICE_IDS, plugin=self)
            # for webusb transport, use custom enumerate function:
            self.device_manager().register_enumerate_func(self.enumerate)
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False

    @runs_in_hwd_thread
    def enumerate(self):
        from keepkeylib.transport_webusb import WebUsbTransport
        results = []
        for dev in WebUsbTransport.enumerate():
            path = self._dev_to_str(dev)
            results.append(Device(path=path,
                                  interface_number=-1,
                                  id_=path,
                                  product_key=(dev.getVendorID(), dev.getProductID()),
                                  usage_page=0,
                                  transport_ui_string=f"webusb:{path}"))
        return results

    @staticmethod
    def _dev_to_str(dev: "usb1.USBDevice") -> str:
        return ":".join(str(x) for x in ["%03i" % (dev.getBusNumber(),)] + dev.getPortNumberList())

    @runs_in_hwd_thread
    def hid_transport(self, pair):
        from keepkeylib.transport_hid import HidTransport
        return HidTransport(pair)

    @runs_in_hwd_thread
    def webusb_transport(self, device):
        from keepkeylib.transport_webusb import WebUsbTransport
        for dev in WebUsbTransport.enumerate():
            if device.path == self._dev_to_str(dev):
                return WebUsbTransport(dev)

    @runs_in_hwd_thread
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

    @runs_in_hwd_thread
    def _try_webusb(self, device):
        self.logger.info("Trying to connect over WebUSB...")
        try:
            return self.webusb_transport(device)
        except BaseException as e:
            self.logger.info(f"cannot connect at {device.path} {e}")
            return None

    @runs_in_hwd_thread
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

    @runs_in_hwd_thread
    def get_client(self, keystore, force_pair=True, *,
                   devices=None, allow_user_interaction=True) -> Optional['KeepKeyClient']:
        client = super().get_client(keystore, force_pair,
                                    devices=devices,
                                    allow_user_interaction=allow_user_interaction)
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def get_coin_name(self):
        return "Testnet" if constants.net.TESTNET else "Bitcoin"

    @runs_in_hwd_thread
    def _initialize_device(self, settings, method, device_id, handler):
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
            word_count = 24  # looks like this value is ignored by the device, but it has to be one of {12,18,24}
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

    def _make_node_path(self, xpub: str, address_n: Sequence[int]):
        bip32node = BIP32Node.from_xkey(xpub)
        node = self.types.HDNodeType(
            depth=bip32node.depth,
            fingerprint=int.from_bytes(bip32node.fingerprint, 'big'),
            child_num=int.from_bytes(bip32node.child_number, 'big'),
            chain_code=bip32node.chaincode,
            public_key=bip32node.eckey.get_public_key_bytes(compressed=True),
        )
        return self.types.HDNodePathType(node=node, address_n=address_n)

    def get_keepkey_input_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.SPENDWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.SPENDP2SHWITNESS
        if electrum_txin_type in ('p2pkh',):
            return self.types.SPENDADDRESS
        if electrum_txin_type in ('p2sh',):
            return self.types.SPENDMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def get_keepkey_output_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.PAYTOWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.PAYTOP2SHWITNESS
        if electrum_txin_type in ('p2pkh',):
            return self.types.PAYTOADDRESS
        if electrum_txin_type in ('p2sh',):
            return self.types.PAYTOMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    @runs_in_hwd_thread
    def sign_transaction(self, keystore, tx: PartialTransaction, prev_tx):
        self.prev_tx = prev_tx
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, for_sig=True, keystore=keystore)
        outputs = self.tx_outputs(tx, keystore=keystore)
        signatures = client.sign_tx(self.get_coin_name(), inputs, outputs,
                                    lock_time=tx.locktime, version=tx.version)[0]
        sighash = Sighash.to_sigbytes(Sighash.ALL)
        signatures = [(sig + sighash) for sig in signatures]
        tx.update_signatures(signatures)

    @runs_in_hwd_thread
    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        client = self.get_client(keystore)
        if not client.atleast_version(1, 3):
            keystore.handler.show_error(_("Your device firmware is too old"))
            return
        deriv_suffix = wallet.get_address_index(address)
        derivation = keystore.get_derivation_prefix()
        address_path = "%s/%d/%d"%(derivation, *deriv_suffix)
        address_n = client.expand_path(address_path)
        script_type = self.get_keepkey_input_script_type(wallet.txin_type)

        # prepare multisig, if available:
        desc = wallet.get_script_descriptor_for_address(address)
        if multi := desc.get_simple_multisig():
            multisig = self._make_multisig(multi)
        else:
            multisig = None

        client.get_address(self.get_coin_name(), address_n, True, multisig=multisig, script_type=script_type)

    def tx_inputs(self, tx: Transaction, *, for_sig=False, keystore: 'KeepKey_KeyStore' = None):
        inputs = []
        for txin in tx.inputs():
            txinputtype = self.types.TxInputType()
            if txin.is_coinbase_input():
                prev_hash = b"\x00"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    assert isinstance(tx, PartialTransaction)
                    assert isinstance(txin, PartialTxInput)
                    assert keystore
                    desc = txin.script_descriptor
                    assert desc
                    if multi := desc.get_simple_multisig():
                        multisig = self._make_multisig(multi)
                    else:
                        multisig = None
                    script_type = self.get_keepkey_input_script_type(desc.to_legacy_electrum_script_type())
                    txinputtype = self.types.TxInputType(
                        script_type=script_type,
                        multisig=multisig)
                    my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txin)
                    if full_path:
                        txinputtype.address_n.extend(full_path)

                prev_hash = txin.prevout.txid
                prev_index = txin.prevout.out_idx

            if txin.value_sats() is not None:
                txinputtype.amount = txin.value_sats()
            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if txin.script_sig is not None:
                txinputtype.script_sig = txin.script_sig

            txinputtype.sequence = txin.nsequence

            inputs.append(txinputtype)

        return inputs

    def _make_multisig(self, desc: descriptor.MultisigDescriptor):
        pubkeys = []
        for pubkey_provider in desc.pubkeys:
            assert not pubkey_provider.is_range()
            assert pubkey_provider.extkey is not None
            xpub = pubkey_provider.pubkey
            der_suffix = pubkey_provider.get_der_suffix_int_list()
            pubkeys.append(self._make_node_path(xpub, der_suffix))
        return self.types.MultisigRedeemScriptType(
            pubkeys=pubkeys,
            signatures=[b''] * len(pubkeys),
            m=desc.thresh)

    def tx_outputs(self, tx: PartialTransaction, *, keystore: 'KeepKey_KeyStore'):

        def create_output_by_derivation():
            desc = txout.script_descriptor
            assert desc
            script_type = self.get_keepkey_output_script_type(desc.to_legacy_electrum_script_type())
            if multi := desc.get_simple_multisig():
                multisig = self._make_multisig(multi)
            else:
                multisig = None
            my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txout)
            assert full_path
            txoutputtype = self.types.TxOutputType(
                multisig=multisig,
                amount=txout.value,
                address_n=full_path,
                script_type=script_type)
            return txoutputtype

        def create_output_by_address():
            txoutputtype = self.types.TxOutputType()
            txoutputtype.amount = txout.value
            if address:
                txoutputtype.script_type = self.types.PAYTOADDRESS
                txoutputtype.address = address
            else:
                txoutputtype.script_type = self.types.PAYTOOPRETURN
                txoutputtype.op_return_data = trezor_validate_op_return_output_and_get_data(txout)
            return txoutputtype

        outputs = []
        has_change = False
        any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)

        for txout in tx.outputs():
            address = txout.address
            use_create_by_derivation = False

            if txout.is_mine and not has_change:
                # prioritise hiding outputs on the 'change' branch from user
                # because no more than one change address allowed
                if txout.is_change == any_output_on_change_branch:
                    use_create_by_derivation = True
                    has_change = True

            if use_create_by_derivation:
                txoutputtype = create_output_by_derivation()
            else:
                txoutputtype = create_output_by_address()
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx: Optional[Transaction]):
        t = self.types.TransactionType()
        if tx is None:
            # probably for segwit input and we don't need this prev txn
            return t
        tx.deserialize()
        t.version = tx.version
        t.lock_time = tx.locktime
        inputs = self.tx_inputs(tx)
        t.inputs.extend(inputs)
        for out in tx.outputs():
            o = t.bin_outputs.add()
            o.amount = out.value
            o.script_pubkey = out.scriptpubkey
        return t

    # This function is called from the TREZOR libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        return self.electrum_tx_to_txtype(tx)

    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet=True) -> str:
        if new_wallet:
            return 'keepkey_start' if device_info.initialized else 'keepkey_not_initialized'
        else:
            return 'keepkey_unlock'

    # insert keepkey pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'keepkey_start': {
                'next': 'keepkey_xpub',
            },
            'keepkey_xpub': {
                'next': lambda d: wizard.wallet_password_view(d) if wizard.last_cosigner(d) else 'multisig_cosigner_keystore',
                'accept': wizard.maybe_master_pubkey,
                'last': lambda d: wizard.is_single_password() and wizard.last_cosigner(d)
            },
            'keepkey_not_initialized': {
                'next': 'keepkey_choose_new_recover',
            },
            'keepkey_choose_new_recover': {
                'next': 'keepkey_do_init',
            },
            'keepkey_do_init': {
                'next': 'keepkey_start',
            },
            'keepkey_unlock': {
                'last': True
            },
        }
        wizard.navmap_merge(views)
