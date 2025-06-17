from typing import Optional, TYPE_CHECKING, Sequence

from electrum.util import UserFacingException
from electrum.bip32 import BIP32Node
from electrum import descriptor
from electrum import constants
from electrum.i18n import _
from electrum.plugin import Device, runs_in_hwd_thread
from electrum.transaction import Transaction, PartialTransaction, PartialTxInput, Sighash
from electrum.keystore import Hardware_KeyStore

from electrum.hw_wallet import HW_PluginBase
from electrum.hw_wallet.plugin import is_any_tx_output_on_change_branch, trezor_validate_op_return_output_and_get_data

if TYPE_CHECKING:
    from .client import SafeTClient
    from electrum.plugin import DeviceInfo
    from electrum.wizard import NewWalletWizard

# Safe-T mini initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)


class SafeTKeyStore(Hardware_KeyStore):
    hw_type = 'safe_t'
    device = 'Safe-T mini'

    plugin: 'SafeTPlugin'

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


class SafeTPlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, types

    firmware_URL = 'https://safe-t.io'
    libraries_URL = 'https://github.com/archos-safe-t/python-safet'
    minimum_firmware = (1, 0, 5)
    keystore_class = SafeTKeyStore
    minimum_library = (0, 1, 0)
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return

        from . import client
        from . import transport
        import safetlib.messages
        self.client_class = client.SafeTClient
        self.types = safetlib.messages
        self.DEVICE_IDS = ('Safe-T mini',)

        self.transport_handler = transport.SafeTTransport()
        self.device_manager().register_enumerate_func(self.enumerate)

    def get_library_version(self):
        import safetlib
        try:
            return safetlib.__version__
        except AttributeError:
            return 'unknown'

    @runs_in_hwd_thread
    def enumerate(self):
        devices = self.transport_handler.enumerate_devices()
        return [Device(path=d.get_path(),
                       interface_number=-1,
                       id_=d.get_path(),
                       product_key='Safe-T mini',
                       usage_page=0,
                       transport_ui_string=d.get_path())
                for d in devices]

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        try:
            self.logger.info(f"connecting to device at {device.path}")
            transport = self.transport_handler.get_transport(device.path)
        except BaseException as e:
            self.logger.info(f"cannot connect at {device.path} {e}")
            return None

        if not transport:
            self.logger.info(f"cannot connect at {device.path}")
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
                   devices=None, allow_user_interaction=True) -> Optional['SafeTClient']:
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

        if method == TIM_RECOVER:
            handler.show_error(_(
                "You will be asked to enter 24 words regardless of your "
                "seed's actual length.  If you enter a word incorrectly or "
                "misspell it, you cannot change it or go back - you will need "
                "to start again from the beginning.\n\nSo please enter "
                "the words carefully!"),
                blocking=True)

        language = 'english'
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

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

    def get_safet_input_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.InputScriptType.SPENDWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.InputScriptType.SPENDP2SHWITNESS
        if electrum_txin_type in ('p2pkh',):
            return self.types.InputScriptType.SPENDADDRESS
        if electrum_txin_type in ('p2sh',):
            return self.types.InputScriptType.SPENDMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def get_safet_output_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.OutputScriptType.PAYTOWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.OutputScriptType.PAYTOP2SHWITNESS
        if electrum_txin_type in ('p2pkh',):
            return self.types.OutputScriptType.PAYTOADDRESS
        if electrum_txin_type in ('p2sh',):
            return self.types.OutputScriptType.PAYTOMULTISIG
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
        if not client.atleast_version(1, 0):
            keystore.handler.show_error(_("Your device firmware is too old"))
            return
        deriv_suffix = wallet.get_address_index(address)
        derivation = keystore.get_derivation_prefix()
        address_path = "%s/%d/%d"%(derivation, *deriv_suffix)
        address_n = client.expand_path(address_path)
        script_type = self.get_safet_input_script_type(wallet.txin_type)

        # prepare multisig, if available:
        desc = wallet.get_script_descriptor_for_address(address)
        if multi := desc.get_simple_multisig():
            multisig = self._make_multisig(multi)
        else:
            multisig = None

        client.get_address(self.get_coin_name(), address_n, True, multisig=multisig, script_type=script_type)

    def tx_inputs(self, tx: Transaction, *, for_sig=False, keystore: 'SafeTKeyStore' = None):
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
                    script_type = self.get_safet_input_script_type(desc.to_legacy_electrum_script_type())
                    txinputtype = self.types.TxInputType(
                        script_type=script_type,
                        multisig=multisig)
                    my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txin)
                    if full_path:
                        txinputtype._extend_address_n(full_path)

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

    def tx_outputs(self, tx: PartialTransaction, *, keystore: 'SafeTKeyStore'):

        def create_output_by_derivation():
            desc = txout.script_descriptor
            assert desc
            script_type = self.get_safet_output_script_type(desc.to_legacy_electrum_script_type())
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
                txoutputtype.script_type = self.types.OutputScriptType.PAYTOADDRESS
                txoutputtype.address = address
            else:
                txoutputtype.script_type = self.types.OutputScriptType.PAYTOOPRETURN
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
                # note: ^ restriction can be removed once we require fw
                # that has https://github.com/trezor/trezor-mcu/pull/306
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
        t._extend_inputs(inputs)
        for out in tx.outputs():
            o = t._add_bin_outputs()
            o.amount = out.value
            o.script_pubkey = out.scriptpubkey
        return t

    # This function is called from the TREZOR libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        return self.electrum_tx_to_txtype(tx)

    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet=True) -> str:
        if new_wallet:
            return 'safet_start' if device_info.initialized else 'safet_not_initialized'
        else:
            return 'safet_unlock'

    # insert safe_t pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'safet_start': {
                'next': 'safet_xpub',
            },
            'safet_xpub': {
                'next': lambda d: wizard.wallet_password_view(d) if wizard.last_cosigner(d) else 'multisig_cosigner_keystore',
                'accept': wizard.maybe_master_pubkey,
                'last': lambda d: wizard.is_single_password() and wizard.last_cosigner(d)
            },
            'safet_not_initialized': {
                'next': 'safet_choose_new_recover',
            },
            'safet_choose_new_recover': {
                'next': 'safet_do_init',
            },
            'safet_do_init': {
                'next': 'safet_start',
            },
            'safet_unlock': {
                'last': True
            },
        }
        wizard.navmap_merge(views)
