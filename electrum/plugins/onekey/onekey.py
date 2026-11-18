from electrum.bip32 import convert_bip32_strpath_to_intpath
from electrum.hw_wallet import HW_PluginBase
from electrum.hw_wallet.plugin import trezor_validate_op_return_output_and_get_data
from electrum.i18n import _
from electrum.keystore import Hardware_KeyStore
from electrum.plugin import Device, runs_in_hwd_thread
from electrum.transaction import PartialTransaction, Sighash
from electrum.util import UserFacingException


class OneKeyKeyStore(Hardware_KeyStore):
    hw_type = "onekey"
    device = "OneKey"

    def decrypt_message(self, sequence, message, password):
        raise UserFacingException(_("Message decryption is not supported by this OneKey plugin."))

    def sign_message(self, sequence, message, password, *, script_type=None):
        raise UserFacingException(_("Message signing is not supported by this OneKey plugin."))

    def sign_transaction(self, tx, password):
        if not tx.is_complete():
            self.plugin.sign_transaction(self, tx)


class OneKeyPlugin(HW_PluginBase):
    keystore_class = OneKeyKeyStore
    DEVICE_IDS = ("OneKey",)
    SUPPORTED_XTYPES = ("standard", "p2wpkh-p2sh", "p2wpkh")
    minimum_library = (0, 20, 1)
    maximum_library = (0, 21)
    libraries_URL = "https://pypi.org/project/trezor/"

    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.libraries_available = self.check_libraries_available()
        if self.libraries_available:
            self.device_manager().register_enumerate_func(self.enumerate)

    def get_library_version(self):
        from .client import LIBRARY_VERSION
        return LIBRARY_VERSION

    @runs_in_hwd_thread
    def enumerate(self):
        import usb1
        from .transport import USB_IDS, device_path

        with usb1.USBContext() as context:
            return [
                Device(path=device_path(device), interface_number=-1,
                       id_=device_path(device), product_key="OneKey", usage_page=0,
                       transport_ui_string="USB")
                for device in context.getDeviceIterator(skip_on_error=True)
                if (device.getVendorID(), device.getProductID()) == USB_IDS
            ]

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        from .client import OneKeyClient
        return OneKeyClient(device.path, handler, self)

    @runs_in_hwd_thread
    def show_address(self, wallet, address, keystore=None):
        keystore = keystore or wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        if wallet.txin_type not in ("p2pkh", "p2wpkh-p2sh", "p2wpkh"):
            raise UserFacingException(_("Only single-signature legacy and SegWit wallets are supported."))
        path = convert_bip32_strpath_to_intpath(keystore.get_derivation_prefix())
        path.extend(wallet.get_address_index(address))
        self.get_client(keystore).show_address(path, wallet.txin_type, address)

    @runs_in_hwd_thread
    def sign_transaction(self, keystore, tx: PartialTransaction):
        from trezorlib import messages
        from .client import INPUT_SCRIPT_TYPES, OUTPUT_SCRIPT_TYPES

        inputs = []
        previous = {}
        for txin in tx.inputs():
            desc = txin.script_descriptor
            if not txin.is_mine or desc is None or desc.get_simple_multisig():
                raise UserFacingException(_("Only single-signature inputs from this OneKey wallet are supported."))
            script_type = desc.to_legacy_electrum_script_type()
            if script_type not in ("p2pkh", "p2wpkh-p2sh", "p2wpkh"):
                raise UserFacingException(_("Unsupported OneKey input script type."))
            if txin.sighash not in (None, Sighash.ALL):
                raise UserFacingException(_("OneKey requires SIGHASH_ALL."))
            pubkey, path = keystore.find_my_pubkey_in_txinout(txin)
            if not path:
                raise UserFacingException(_("Input does not belong to this OneKey wallet."))
            if txin.utxo is None:
                raise UserFacingException(_("Missing previous tx."))
            previous[txin.prevout.txid] = self._previous_transaction(txin.utxo)
            inputs.append(messages.TxInputType(
                prev_hash=txin.prevout.txid, prev_index=txin.prevout.out_idx,
                amount=txin.value_sats(), sequence=txin.nsequence,
                address_n=path, script_type=INPUT_SCRIPT_TYPES[script_type],
            ))

        outputs = []
        for txout in tx.outputs():
            if txout.is_mine and txout.is_change:
                desc = txout.script_descriptor
                if desc is None or desc.get_simple_multisig():
                    raise UserFacingException(_("Unsupported OneKey change script."))
                script_type = desc.to_legacy_electrum_script_type()
                if script_type not in OUTPUT_SCRIPT_TYPES:
                    raise UserFacingException(_("Unsupported OneKey change script."))
                pubkey, path = keystore.find_my_pubkey_in_txinout(txout)
                if not path:
                    raise UserFacingException(_("Change does not belong to this OneKey wallet."))
                outputs.append(messages.TxOutputType(
                    amount=txout.value, address_n=path,
                    script_type=OUTPUT_SCRIPT_TYPES[script_type],
                ))
            elif txout.address:
                outputs.append(messages.TxOutputType(
                    amount=txout.value, address=txout.address,
                    script_type=messages.OutputScriptType.PAYTOADDRESS,
                ))
            else:
                outputs.append(messages.TxOutputType(
                    amount=txout.value, script_type=messages.OutputScriptType.PAYTOOPRETURN,
                    op_return_data=trezor_validate_op_return_output_and_get_data(txout),
                ))

        signatures = self.get_client(keystore).sign_tx(
            inputs, outputs, previous, version=tx.version, lock_time=tx.locktime,
        )
        if len(signatures) != len(inputs) or any(not sig for sig in signatures):
            raise UserFacingException(_("OneKey did not sign all inputs."))
        tx.update_signatures([sig + Sighash.to_sigbytes(Sighash.ALL) for sig in signatures])
        if not tx.is_complete():
            raise UserFacingException(_("OneKey returned invalid transaction signatures."))

    @staticmethod
    def _previous_transaction(tx):
        from trezorlib import messages

        return messages.TransactionType(
            version=tx.version, lock_time=tx.locktime,
            inputs=[messages.TxInputType(
                prev_hash=txin.prevout.txid, prev_index=txin.prevout.out_idx,
                script_sig=txin.script_sig, sequence=txin.nsequence,
            ) for txin in tx.inputs()],
            bin_outputs=[messages.TxOutputBinType(
                amount=txout.value, script_pubkey=txout.scriptpubkey,
            ) for txout in tx.outputs()],
        )

    def wizard_entry_for_device(self, device_info, *, new_wallet=True):
        if not device_info.initialized:
            return "onekey_not_initialized"
        return "onekey_start" if new_wallet else "onekey_unlock"

    def extend_wizard(self, wizard):
        wizard.navmap_merge({
            "onekey_start": {"next": "onekey_xpub"},
            "onekey_xpub": {
                "next": lambda d: wizard.wallet_password_view(d),
                "accept": wizard.maybe_master_pubkey,
                "last": lambda d: wizard.is_single_password(),
            },
            "onekey_not_initialized": {},
            "onekey_unlock": {"last": True},
        })
