#
# BitBox02 Electrum plugin code.
#

import hid
from typing import TYPE_CHECKING, Dict, Tuple, Optional, List, Any, Callable

from electrum import bip32, constants
from electrum.i18n import _
from electrum.keystore import Hardware_KeyStore
from electrum.transaction import PartialTransaction
from electrum.wallet import Standard_Wallet, Multisig_Wallet, Deterministic_Wallet
from electrum.util import bh2u, UserFacingException
from electrum.base_wizard import ScriptTypeNotSupported, BaseWizard
from electrum.logging import get_logger
from electrum.plugin import Device, DeviceInfo
from electrum.simple_config import SimpleConfig
from electrum.json_db import StoredDict
from electrum.storage import get_derivation_used_for_hw_device_encryption
from electrum.bitcoin import OnchainOutputType

import electrum.bitcoin as bitcoin
import electrum.ecc as ecc

from ..hw_wallet import HW_PluginBase, HardwareClientBase


try:
    from bitbox02 import bitbox02
    from bitbox02 import util
    from bitbox02.communication import (
        devices,
        HARDENED,
        u2fhid,
        bitbox_api_protocol,
        FirmwareVersionOutdatedException,
    )
    requirements_ok = True
except ImportError:
    requirements_ok = False


_logger = get_logger(__name__)


class BitBox02Client(HardwareClientBase):
    # handler is a BitBox02_Handler, importing it would lead to a circular dependency
    def __init__(self, handler: Any, device: Device, config: SimpleConfig, *, plugin: HW_PluginBase):
        HardwareClientBase.__init__(self, plugin=plugin)
        self.bitbox02_device = None  # type: Optional[bitbox02.BitBox02]
        self.handler = handler
        self.device_descriptor = device
        self.config = config
        self.bitbox_hid_info = None
        if self.config.get("bitbox02") is None:
            bitbox02_config: dict = {
                "remote_static_noise_keys": [],
                "noise_privkey": None,
            }
            self.config.set_key("bitbox02", bitbox02_config)

        bitboxes = devices.get_any_bitbox02s()
        for bitbox in bitboxes:
            if (
                bitbox["path"] == self.device_descriptor.path
                and bitbox["interface_number"]
                == self.device_descriptor.interface_number
            ):
                self.bitbox_hid_info = bitbox
        if self.bitbox_hid_info is None:
            raise Exception("No BitBox02 detected")

    def is_initialized(self) -> bool:
        return True

    def close(self):
        with self.device_manager().hid_lock:
            try:
                self.bitbox02_device.close()
            except:
                pass

    def has_usable_connection_with_device(self) -> bool:
        if self.bitbox_hid_info is None:
            return False
        return True

    def pairing_dialog(self, wizard: bool = True):
        def pairing_step(code: str, device_response: Callable[[], bool]) -> bool:
            msg = "Please compare and confirm the pairing code on your BitBox02:\n" + code
            self.handler.show_message(msg)
            try:
                res = device_response()
            except:
                # Close the hid device on exception
                with self.device_manager().hid_lock:
                    hid_device.close()
                raise
            finally:
                self.handler.finished()
            return res

        def exists_remote_static_pubkey(pubkey: bytes) -> bool:
            bitbox02_config = self.config.get("bitbox02")
            noise_keys = bitbox02_config.get("remote_static_noise_keys")
            if noise_keys is not None:
                if pubkey.hex() in [noise_key for noise_key in noise_keys]:
                    return True
            return False

        def set_remote_static_pubkey(pubkey: bytes) -> None:
            if not exists_remote_static_pubkey(pubkey):
                bitbox02_config = self.config.get("bitbox02")
                if bitbox02_config.get("remote_static_noise_keys") is not None:
                    bitbox02_config["remote_static_noise_keys"].append(pubkey.hex())
                else:
                    bitbox02_config["remote_static_noise_keys"] = [pubkey.hex()]
                self.config.set_key("bitbox02", bitbox02_config)

        def get_noise_privkey() -> Optional[bytes]:
            bitbox02_config = self.config.get("bitbox02")
            privkey = bitbox02_config.get("noise_privkey")
            if privkey is not None:
                return bytes.fromhex(privkey)
            return None

        def set_noise_privkey(privkey: bytes) -> None:
            bitbox02_config = self.config.get("bitbox02")
            bitbox02_config["noise_privkey"] = privkey.hex()
            self.config.set_key("bitbox02", bitbox02_config)

        def attestation_warning() -> None:
            self.handler.show_error(
                "The BitBox02 attestation failed.\nTry reconnecting the BitBox02.\nWarning: The device might not be genuine, if the\n problem persists please contact Shift support.",
                blocking=True
            )

        class NoiseConfig(bitbox_api_protocol.BitBoxNoiseConfig):
            """NoiseConfig extends BitBoxNoiseConfig"""

            def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
                return pairing_step(code, device_response)

            def attestation_check(self, result: bool) -> None:
                if not result:
                    attestation_warning()

            def contains_device_static_pubkey(self, pubkey: bytes) -> bool:
                return exists_remote_static_pubkey(pubkey)

            def add_device_static_pubkey(self, pubkey: bytes) -> None:
                return set_remote_static_pubkey(pubkey)

            def get_app_static_privkey(self) -> Optional[bytes]:
                return get_noise_privkey()

            def set_app_static_privkey(self, privkey: bytes) -> None:
                return set_noise_privkey(privkey)

        if self.bitbox02_device is None:
            with self.device_manager().hid_lock:
                hid_device = hid.device()
                hid_device.open_path(self.bitbox_hid_info["path"])


            bitbox02_device = bitbox02.BitBox02(
                transport=u2fhid.U2FHid(hid_device),
                device_info=self.bitbox_hid_info,
                noise_config=NoiseConfig(),
            )
            try:
                bitbox02_device.check_min_version()
            except FirmwareVersionOutdatedException:
                raise
            self.bitbox02_device = bitbox02_device

        self.fail_if_not_initialized()

    def fail_if_not_initialized(self) -> None:
        assert self.bitbox02_device
        if not self.bitbox02_device.device_info()["initialized"]:
            raise Exception(
                "Please initialize the BitBox02 using the BitBox app first before using the BitBox02 in electrum"
            )

    def coin_network_from_electrum_network(self) -> int:
        if constants.net.TESTNET:
            return bitbox02.btc.TBTC
        return bitbox02.btc.BTC

    def get_password_for_storage_encryption(self) -> str:
        derivation = get_derivation_used_for_hw_device_encryption()
        derivation_list = bip32.convert_bip32_path_to_list_of_uint32(derivation)
        xpub = self.bitbox02_device.electrum_encryption_key(derivation_list)
        node = bip32.BIP32Node.from_xkey(xpub, net = constants.BitcoinMainnet()).subkey_at_public_derivation(())
        return node.eckey.get_public_key_bytes(compressed=True).hex()

    def get_xpub(self, bip32_path: str, xtype: str, *, display: bool = False) -> str:
        if self.bitbox02_device is None:
            self.pairing_dialog(wizard=False)

        if self.bitbox02_device is None:
            raise Exception(
                "Need to setup communication first before attempting any BitBox02 calls"
            )

        self.fail_if_not_initialized()

        xpub_keypath = bip32.convert_bip32_path_to_list_of_uint32(bip32_path)
        coin_network = self.coin_network_from_electrum_network()

        if xtype == "p2wpkh":
            if coin_network == bitbox02.btc.BTC:
                out_type = bitbox02.btc.BTCPubRequest.ZPUB
            else:
                out_type = bitbox02.btc.BTCPubRequest.VPUB
        elif xtype == "p2wpkh-p2sh":
            if coin_network == bitbox02.btc.BTC:
                out_type = bitbox02.btc.BTCPubRequest.YPUB
            else:
                out_type = bitbox02.btc.BTCPubRequest.UPUB
        elif xtype == "p2wsh":
            if coin_network == bitbox02.btc.BTC:
                out_type = bitbox02.btc.BTCPubRequest.CAPITAL_ZPUB
            else:
                out_type = bitbox02.btc.BTCPubRequest.CAPITAL_VPUB
        # The other legacy types are not supported
        else:
            raise Exception("invalid xtype:{}".format(xtype))

        return self.bitbox02_device.btc_xpub(
            keypath=xpub_keypath,
            xpub_type=out_type,
            coin=coin_network,
            display=display,
        )

    def request_root_fingerprint_from_device(self) -> str:
        if self.bitbox02_device is None:
            raise Exception(
                "Need to setup communication first before attempting any BitBox02 calls"
            )

        return self.bitbox02_device.root_fingerprint().hex()

    def is_pairable(self) -> bool:
        if self.bitbox_hid_info is None:
            return False
        return True

    def btc_multisig_config(
        self, coin, bip32_path: List[int], wallet: Multisig_Wallet
    ):
        """
        Set and get a multisig config with the current device and some other arbitrary xpubs.
        Registers it on the device if not already registered.
        """

        if self.bitbox02_device is None:
            raise Exception(
                "Need to setup communication first before attempting any BitBox02 calls"
            )

        account_keypath = bip32_path[:4]
        xpubs = wallet.get_master_public_keys()
        our_xpub = self.get_xpub(
            bip32.convert_bip32_intpath_to_strpath(account_keypath), "p2wsh"
        )

        multisig_config = bitbox02.btc.BTCScriptConfig(
            multisig=bitbox02.btc.BTCScriptConfig.Multisig(
                threshold=wallet.m,
                xpubs=[util.parse_xpub(xpub) for xpub in xpubs],
                our_xpub_index=xpubs.index(our_xpub),
            )
        )

        is_registered = self.bitbox02_device.btc_is_script_config_registered(
            coin, multisig_config, account_keypath
        )
        if not is_registered:
            name = self.handler.name_multisig_account()
            try:
                self.bitbox02_device.btc_register_script_config(
                    coin=coin,
                    script_config=multisig_config,
                    keypath=account_keypath,
                    name=name,
                )
            except bitbox02.DuplicateEntryException:
                raise
            except:
                raise UserFacingException("Failed to register multisig\naccount configuration on BitBox02")
        return multisig_config

    def show_address(
        self, bip32_path: str, address_type: str, wallet: Deterministic_Wallet
    ) -> str:

        if self.bitbox02_device is None:
            raise Exception(
                "Need to setup communication first before attempting any BitBox02 calls"
            )

        address_keypath = bip32.convert_bip32_path_to_list_of_uint32(bip32_path)
        coin_network = self.coin_network_from_electrum_network()

        if address_type == "p2wpkh":
            script_config = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
            )
        elif address_type == "p2wpkh-p2sh":
            script_config = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
            )
        elif address_type == "p2wsh":
            if type(wallet) is Multisig_Wallet:
                script_config = self.btc_multisig_config(
                    coin_network, address_keypath, wallet
                )
            else:
                raise Exception("Can only use p2wsh with multisig wallets")
        else:
            raise Exception(
                "invalid address xtype: {} is not supported by the BitBox02".format(
                    address_type
                )
            )

        return self.bitbox02_device.btc_address(
            keypath=address_keypath,
            coin=coin_network,
            script_config=script_config,
            display=True,
        )

    def sign_transaction(
        self,
        keystore: Hardware_KeyStore,
        tx: PartialTransaction,
        wallet: Deterministic_Wallet,
    ):
        if tx.is_complete():
            return

        if self.bitbox02_device is None:
            raise Exception(
                "Need to setup communication first before attempting any BitBox02 calls"
            )

        coin = bitbox02.btc.BTC
        if constants.net.TESTNET:
            coin = bitbox02.btc.TBTC

        tx_script_type = None

        # Build BTCInputType list
        inputs = []
        for txin in tx.inputs():
            my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txin)

            if full_path is None:
                raise Exception(
                    "A wallet owned pubkey was not found in the transaction input to be signed"
                )

            prev_tx = txin.utxo
            if prev_tx is None:
                raise UserFacingException(_('Missing previous tx.'))

            prev_inputs: List[bitbox02.BTCPrevTxInputType] = []
            prev_outputs: List[bitbox02.BTCPrevTxOutputType] = []
            for prev_txin in prev_tx.inputs():
                prev_inputs.append(
                    {
                        "prev_out_hash": prev_txin.prevout.txid[::-1],
                        "prev_out_index": prev_txin.prevout.out_idx,
                        "signature_script": prev_txin.script_sig,
                        "sequence": prev_txin.nsequence,
                    }
                )
            for prev_txout in prev_tx.outputs():
                prev_outputs.append(
                    {
                        "value": prev_txout.value,
                        "pubkey_script": prev_txout.scriptpubkey,
                    }
                )

            inputs.append(
                {
                    "prev_out_hash": txin.prevout.txid[::-1],
                    "prev_out_index": txin.prevout.out_idx,
                    "prev_out_value": txin.value_sats(),
                    "sequence": txin.nsequence,
                    "keypath": full_path,
                    "script_config_index": 0,
                    "prev_tx": {
                        "version": prev_tx.version,
                        "locktime": prev_tx.locktime,
                        "inputs": prev_inputs,
                        "outputs": prev_outputs,
                    },
                }
            )

            if tx_script_type == None:
                tx_script_type = txin.script_type
            elif tx_script_type != txin.script_type:
                raise Exception("Cannot mix different input script types")

        if tx_script_type == "p2wpkh":
            tx_script_type = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
            )
        elif tx_script_type == "p2wpkh-p2sh":
            tx_script_type = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
            )
        elif tx_script_type == "p2wsh":
            if type(wallet) is Multisig_Wallet:
                tx_script_type = self.btc_multisig_config(coin, full_path, wallet)
            else:
                raise Exception("Can only use p2wsh with multisig wallets")
        else:
            raise UserFacingException(
                "invalid input script type: {} is not supported by the BitBox02".format(
                    tx_script_type
                )
            )

        # Build BTCOutputType list
        outputs = []
        for txout in tx.outputs():
            assert txout.address
            # check for change
            if txout.is_change:
                my_pubkey, change_pubkey_path = keystore.find_my_pubkey_in_txinout(txout)
                outputs.append(
                    bitbox02.BTCOutputInternal(
                        keypath=change_pubkey_path, value=txout.value, script_config_index=0,
                    )
                )
            else:
                addrtype, pubkey_hash = bitcoin.address_to_hash(txout.address)
                if addrtype == OnchainOutputType.P2PKH:
                    output_type = bitbox02.btc.P2PKH
                elif addrtype == OnchainOutputType.P2SH:
                    output_type = bitbox02.btc.P2SH
                elif addrtype == OnchainOutputType.WITVER0_P2WPKH:
                    output_type = bitbox02.btc.P2WPKH
                elif addrtype == OnchainOutputType.WITVER0_P2WSH:
                    output_type = bitbox02.btc.P2WSH
                else:
                    raise UserFacingException(
                        "Received unsupported output type during transaction signing: {} is not supported by the BitBox02".format(
                            addrtype
                        )
                    )
                outputs.append(
                    bitbox02.BTCOutputExternal(
                        output_type=output_type,
                        output_hash=pubkey_hash,
                        value=txout.value,
                    )
                )

        if type(wallet) is Standard_Wallet:
            keypath_account = full_path[:3]
        elif type(wallet) is Multisig_Wallet:
            keypath_account = full_path[:4]
        else:
            raise Exception(
                "BitBox02 does not support this wallet type: {}".format(type(wallet))
            )

        sigs = self.bitbox02_device.btc_sign(
            coin,
            [bitbox02.btc.BTCScriptConfigWithKeypath(
                script_config=tx_script_type,
                keypath=keypath_account,
            )],
            inputs=inputs,
            outputs=outputs,
            locktime=tx.locktime,
            version=tx.version,
        )

        # Fill signatures
        if len(sigs) != len(tx.inputs()):
            raise Exception("Incorrect number of inputs signed.")  # Should never occur
        signatures = [bh2u(ecc.der_sig_from_sig_string(x[1])) + "01" for x in sigs]
        tx.update_signatures(signatures)


class BitBox02_KeyStore(Hardware_KeyStore):
    hw_type = "bitbox02"
    device = "BitBox02"
    plugin: "BitBox02Plugin"

    def __init__(self, d: StoredDict):
        super().__init__(d)
        self.force_watching_only = False
        self.ux_busy = False

    def get_client(self):
        return self.plugin.get_client(self)

    def give_error(self, message: Exception, clear_client: bool = False):
        self.logger.info(message)
        if not self.ux_busy:
            self.handler.show_error(message)
        else:
            self.ux_busy = False
        if clear_client:
            self.client = None
        raise UserFacingException(message)

    def decrypt_message(self, pubkey, message, password):
        raise UserFacingException(
            _(
                "Message encryption, decryption and signing are currently not supported for {}"
            ).format(self.device)
        )

    def sign_message(self, sequence, message, password):
        raise UserFacingException(
            _(
                "Message encryption, decryption and signing are currently not supported for {}"
            ).format(self.device)
        )

    def sign_transaction(self, tx: PartialTransaction, password: str):
        if tx.is_complete():
            return
        client = self.get_client()
        assert isinstance(client, BitBox02Client)

        try:
            try:
                self.handler.show_message("Authorize Transaction...")
                client.sign_transaction(self, tx, self.handler.get_wallet())

            finally:
                self.handler.finished()

        except Exception as e:
            self.logger.exception("")
            self.give_error(e, True)
            return

    def show_address(
        self, sequence: Tuple[int, int], txin_type: str, wallet: Deterministic_Wallet
    ):
        client = self.get_client()
        address_path = "{}/{}/{}".format(
            self.get_derivation_prefix(), sequence[0], sequence[1]
        )
        try:
            try:
                self.handler.show_message(_("Showing address ..."))
                dev_addr = client.show_address(address_path, txin_type, wallet)
            finally:
                self.handler.finished()
        except Exception as e:
            self.logger.exception("")
            self.handler.show_error(e)

class BitBox02Plugin(HW_PluginBase):
    keystore_class = BitBox02_KeyStore
    minimum_library = (4, 0, 0)
    DEVICE_IDS = [(0x03EB, 0x2403)]

    SUPPORTED_XTYPES = ("p2wpkh-p2sh", "p2wpkh", "p2wsh")

    def __init__(self, parent: HW_PluginBase, config: SimpleConfig, name: str):
        super().__init__(parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return
        self.device_manager().register_devices(self.DEVICE_IDS, plugin=self)

    def get_library_version(self):
        try:
            from bitbox02 import bitbox02
            version = bitbox02.__version__
        except:
            version = "unknown"
        if requirements_ok:
            return version
        else:
            raise ImportError()

    # handler is a BitBox02_Handler
    def create_client(self, device: Device, handler: Any) -> BitBox02Client:
        if not handler:
            self.handler = handler
        return BitBox02Client(handler, device, self.config, plugin=self)

    def setup_device(
        self, device_info: DeviceInfo, wizard: BaseWizard, purpose: int
    ):
        device_id = device_info.device.id_
        client = self.scan_and_create_client_for_device(device_id=device_id, wizard=wizard)
        assert isinstance(client, BitBox02Client)
        if client.bitbox02_device is None:
            wizard.run_task_without_blocking_gui(
                task=lambda client=client: client.pairing_dialog())
        client.fail_if_not_initialized()
        return client

    def get_xpub(
        self, device_id: str, derivation: str, xtype: str, wizard: BaseWizard
    ):
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(
                _("This type of script is not supported with {}.").format(self.device)
            )
        client = self.scan_and_create_client_for_device(device_id=device_id, wizard=wizard)
        assert isinstance(client, BitBox02Client)
        assert client.bitbox02_device is not None
        return client.get_xpub(derivation, xtype)

    def show_address(
        self,
        wallet: Deterministic_Wallet,
        address: str,
        keystore: BitBox02_KeyStore = None,
    ):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return

        txin_type = wallet.get_txin_type(address)
        sequence = wallet.get_address_index(address)
        keystore.show_address(sequence, txin_type, wallet)

    def show_xpub(self, keystore: BitBox02_KeyStore):
        client = keystore.get_client()
        assert isinstance(client, BitBox02Client)
        derivation = keystore.get_derivation_prefix()
        xtype = keystore.get_bip32_node_for_xpub().xtype
        client.get_xpub(derivation, xtype, display=True)

    def create_device_from_hid_enumeration(self, d: dict, *, product_key) -> 'Device':
        device = super().create_device_from_hid_enumeration(d, product_key=product_key)
        # The BitBox02's product_id is not unique per device, thus use the path instead to
        # distinguish devices.
        id_ = str(d['path'])
        return device._replace(id_=id_)
