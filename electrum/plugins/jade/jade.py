import os
import base64
import json
from typing import Optional, TYPE_CHECKING

from electrum import bip32, constants
from electrum.crypto import sha256
from electrum.i18n import _
from electrum.keystore import Hardware_KeyStore
from electrum.transaction import Transaction
from electrum.wallet import Multisig_Wallet
from electrum.util import UserFacingException
from electrum.logging import get_logger
from electrum.plugin import runs_in_hwd_thread, Device
from electrum.network import Network

from electrum.plugins.hw_wallet import HW_PluginBase, HardwareClientBase
from electrum.plugins.hw_wallet.plugin import OutdatedHwFirmwareException

if TYPE_CHECKING:
    from electrum.plugin import DeviceInfo
    from electrum.wizard import NewWalletWizard

_logger = get_logger(__name__)

#import logging
#LOGGING = logging.INFO
#if LOGGING:
#    logger = logging.getLogger('jade')
#    logger.setLevel(LOGGING)
#    device_logger = logging.getLogger('jade-device')
#    device_logger.setLevel(LOGGING)

try:
    # Do imports
    from .jadepy.jade import JadeAPI
    from serial.tools import list_ports
except ImportError as e:
    _logger.exception('error importing Jade plugin deps')

# Ignore -beta and -rc etc labels
def _versiontuple(v):
    return tuple(map(int, (v.split('-')[0].split('.'))))

def _is_multisig(wallet):
    return type(wallet) is Multisig_Wallet

# Ensure a multisig wallet is registered on Jade hw.
# Derives and returns the deterministic name for that multisig registration
def _register_multisig_wallet(wallet, keystore, address):
    wallet_fingerprint_hash = sha256(wallet.get_fingerprint())
    multisig_name = 'ele' + wallet_fingerprint_hash.hex()[:12]

    # Collect all the signer data in case we need to register the
    # multisig wallet on the Jade hw - NOTE: re-register is a no-op.
    signers = []
    for kstore in wallet.get_keystores():
        fingerprint = kstore.get_root_fingerprint()
        bip32_path_prefix = kstore.get_derivation_prefix()
        derivation_path = bip32.convert_bip32_strpath_to_intpath(bip32_path_prefix)

        # Jade only understands standard xtypes, so convert here
        node = bip32.BIP32Node.from_xkey(kstore.xpub)
        standard_xpub = node._replace(xtype='standard').to_xkey()

        signers.append({'fingerprint': bytes.fromhex(fingerprint),
                        'derivation': derivation_path,
                        'xpub': standard_xpub,
                        'path': []})

    # Check multisig is registered - re-registering is a no-op
    # NOTE: electrum multisigs appear to always be sorted-multisig
    txin_type = wallet.get_txin_type(address)
    keystore.register_multisig(multisig_name, txin_type, True, wallet.m, signers)

    # Return the name used to register the wallet
    return multisig_name

# Helper to adapt Jade's http call/data to Network.send_http_on_proxy()
def _http_request(params):
    # Use the first non-onion url
    url = [url for url in params['urls'] if not url.endswith('.onion')][0]
    method = params['method'].lower()
    json_payload = params.get('data')
    json_response = Network.send_http_on_proxy(method, url, json=json_payload)
    return {'body': json.loads(json_response)}

class Jade_Client(HardwareClientBase):

    @staticmethod
    def _network() -> str:
        return 'localtest' if constants.net.NET_NAME == 'regtest' else constants.net.NET_NAME

    ADDRTYPES = {'standard': 'pkh(k)',
                 'p2pkh': 'pkh(k)',
                 'p2wpkh': 'wpkh(k)',
                 'p2wpkh-p2sh': 'sh(wpkh(k))'}

    MULTI_ADDRTYPES = {'standard': 'sh(multi(k))',
                       'p2sh': 'sh(multi(k))',
                       'p2wsh': 'wsh(multi(k))',
                       'p2wsh-p2sh': 'sh(wsh(multi(k)))'}

    @classmethod
    def _convertAddrType(cls, addrType: str, multisig: bool) -> str:
        return cls.MULTI_ADDRTYPES[addrType] if multisig else cls.ADDRTYPES[addrType]

    def __init__(self, device: str, plugin: HW_PluginBase):
        HardwareClientBase.__init__(self, plugin=plugin)

        # Connect with a small timeout to test connection
        self.jade = JadeAPI.create_serial(device, timeout=1)
        self.jade.connect()

        verinfo = self.jade.get_version_info()
        self.fwversion = _versiontuple(verinfo['JADE_VERSION'])
        self.efusemac = verinfo['EFUSEMAC']
        self.jade.disconnect()

        # Reconnect with a the default timeout for all subsequent calls
        self.jade = JadeAPI.create_serial(device)
        self.jade.connect()

        # Push some host entropy into jade
        self.jade.add_entropy(os.urandom(32))

    @runs_in_hwd_thread
    def authenticate(self):
        # Ensure Jade unlocked - always call hw unit at least once
        # If the hw is already unlocked, this call returns immediately/no-op
        # NOTE: uses provided http/networking which respects any user proxy
        authenticated = False
        while not authenticated:
            authenticated = self.jade.auth_user(self._network(), http_request_fn=_http_request)

    def is_pairable(self):
        return True

    @runs_in_hwd_thread
    def close(self):
        self.jade.disconnect()
        self.jade = None

    @runs_in_hwd_thread
    def is_initialized(self):
        verinfo = self.jade.get_version_info()
        return verinfo['JADE_STATE'] != 'UNINIT'

    def label(self) -> Optional[str]:
        return self.efusemac[-6:]

    def get_soft_device_id(self):
        return f'Jade {self.label()}'

    def device_model_name(self):
        return 'Blockstream Jade'

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        if self.efusemac is None:
            return False

        try:
            verinfo = self.jade.get_version_info()
            return verinfo['EFUSEMAC'] == self.efusemac
        except BaseException:
            return False

    @runs_in_hwd_thread
    def get_xpub(self, bip32_path, xtype):
        self.authenticate()

        # Jade only provides traditional xpubs ...
        path = bip32.convert_bip32_strpath_to_intpath(bip32_path)
        xpub = self.jade.get_xpub(self._network(), path)

        # ... so convert to relevant xtype locally
        node = bip32.BIP32Node.from_xkey(xpub)
        return node._replace(xtype=xtype).to_xkey()

    @runs_in_hwd_thread
    def sign_message(self, bip32_path_prefix, sequence, message):
        self.authenticate()

        path = bip32.convert_bip32_strpath_to_intpath(bip32_path_prefix)
        path.extend(sequence)

        if isinstance(message, bytes) or isinstance(message, bytearray):
            message = message.decode('utf-8')

        # Signature verification does not work with anti-exfil, so stick with default (rfc6979)
        sig = self.jade.sign_message(path, message)
        return base64.b64decode(sig)

    @runs_in_hwd_thread
    def sign_tx(self, txn_bytes, inputs, change):
        self.authenticate()

        # Add some host entropy for AE sigs (although we won't verify)
        for input in inputs:
            if input['path'] is not None:
                input['ae_host_entropy'] = os.urandom(32)
                input['ae_host_commitment'] = os.urandom(32)

        # Map change script type
        for output in change:
            if output and output.get('variant') is not None:
                output['variant'] = self._convertAddrType(output['variant'], False)

        # Pass to Jade to generate signatures
        sig_data = self.jade.sign_tx(self._network(), txn_bytes, inputs, change, use_ae_signatures=True)

        # Extract signatures from returned data (sig[0] is the AE signer-commitment)
        return [sig[1] for sig in sig_data]

    @runs_in_hwd_thread
    def show_address(self, bip32_path_prefix, sequence, txin_type):
        self.authenticate()
        path = bip32.convert_bip32_strpath_to_intpath(bip32_path_prefix)
        path.extend(sequence)
        script_variant = self._convertAddrType(txin_type, multisig=False)
        address = self.jade.get_receive_address(self._network(), path, variant=script_variant)
        return address

    @runs_in_hwd_thread
    def register_multisig(self, multisig_name, txin_type, sorted, threshold, signers):
        self.authenticate()
        variant = self._convertAddrType(txin_type, multisig=True)
        return self.jade.register_multisig(self._network(), multisig_name, variant, sorted, threshold, signers)

    @runs_in_hwd_thread
    def show_address_multi(self, multisig_name, paths):
        self.authenticate()
        return self.jade.get_receive_address(self._network(), paths, multisig_name=multisig_name)

class Jade_KeyStore(Hardware_KeyStore):
    hw_type = 'jade'
    device = 'Jade'

    plugin: 'JadePlugin'

    def decrypt_message(self, sequence, message, password):
        raise UserFacingException(_('Encryption and decryption are not implemented by {}').format(self.device))

    @runs_in_hwd_thread
    def sign_message(self, sequence, message, password, *, script_type=None):
        self.handler.show_message(_("Please confirm signing the message with your Jade device..."))
        try:
            client = self.get_client()
            bip32_path_prefix = self.get_derivation_prefix()
            return client.sign_message(bip32_path_prefix, sequence, message)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return

        self.handler.show_message(_("Preparing to sign transaction ..."))
        try:
            wallet = self.handler.get_wallet()
            is_multisig = _is_multisig(wallet)

            # Fetch inputs of the transaction to sign
            jade_inputs = []
            for txin in tx.inputs():
                pubkey, path = self.find_my_pubkey_in_txinout(txin)
                witness_input = txin.is_segwit()
                redeem_script = Transaction.get_preimage_script(txin)
                input_tx = txin.utxo
                input_tx = bytes.fromhex(input_tx.serialize()) if input_tx is not None else None

                # Build the input and add to the list - include some host entropy for AE sigs (although we won't verify)
                jade_inputs.append({'is_witness': witness_input,
                                    'input_tx': input_tx,
                                    'script': redeem_script,
                                    'path': path})

            # Change detection
            change = [None] * len(tx.outputs())
            for index, txout in enumerate(tx.outputs()):
                if txout.is_mine and txout.is_change:
                    desc = txout.script_descriptor
                    assert desc
                    if is_multisig:
                        # Multisig - wallet details must be registered on Jade hw
                        multisig_name = _register_multisig_wallet(wallet, self, txout.address)

                        # Jade only needs the path suffix(es) and the multisig registration
                        # name to generate the address, as the fixed derivation part is
                        # embedded in the multisig wallet registration record
                        # NOTE: all cosigners have same path suffix
                        path_suffix = wallet.get_address_index(txout.address)
                        paths = [path_suffix] * wallet.n
                        change[index] = {'multisig_name': multisig_name, 'paths': paths}
                    else:
                        # Pass entire path
                        pubkey, path = self.find_my_pubkey_in_txinout(txout)
                        change[index] = {'path':path, 'variant': desc.to_legacy_electrum_script_type()}

            # The txn itself
            txn_bytes = bytes.fromhex(tx.serialize_to_network(include_sigs=False))

            # Request Jade generate the signatures for our inputs.
            # Change details are passed to be validated on the hw (user does not confirm)
            self.handler.show_message(_("Please confirm the transaction details on your Jade device..."))
            client = self.get_client()
            signatures = client.sign_tx(txn_bytes, jade_inputs, change)
            assert len(signatures) == len(tx.inputs())

            # Inject signatures into tx
            for index, (txin, signature) in enumerate(zip(tx.inputs(), signatures)):
                pubkey, path = self.find_my_pubkey_in_txinout(txin)
                if pubkey is not None and signature is not None:
                    tx.add_signature_to_txin(
                        txin_idx=index,
                        signing_pubkey=pubkey,
                        sig=signature,
                    )
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    def show_address(self, sequence, txin_type):
        self.handler.show_message(_("Showing address ..."))
        try:
            client = self.get_client()
            bip32_path_prefix = self.get_derivation_prefix()
            return client.show_address(bip32_path_prefix, sequence, txin_type)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    def register_multisig(self, name, txin_type, sorted, threshold, signers):
        self.handler.show_message(_("Please confirm the multisig wallet details on your Jade device..."))
        try:
            client = self.get_client()
            return client.register_multisig(name, txin_type, sorted, threshold, signers)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    def show_address_multi(self, multisig_name, paths):
        self.handler.show_message(_("Showing address ..."))
        try:
            client = self.get_client()
            return client.show_address_multi(multisig_name, paths)
        finally:
            self.handler.finished()


class JadePlugin(HW_PluginBase):
    keystore_class = Jade_KeyStore
    minimum_library = (0, 0, 1)
    DEVICE_IDS = [(0x10c4, 0xea60), # Development Jade device
                  (0x1a86, 0x55d4), # Retail Blockstream Jade (And some DIY devices)
                  (0x0403, 0x6001), # DIY FTDI Based Devices (Eg: M5StickC-Plus)
                  (0x1a86, 0x7523)] # DIY CH340 Based devices (Eg: ESP32-Wrover)
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
    MIN_SUPPORTED_FW_VERSION = (0, 1, 32)

    # For testing with qemu simulator (experimental)
    SIMULATOR_PATH = None  # 'tcp:127.0.0.1:2222'
    SIMULATOR_TEST_SEED = None  # bytes.fromhex('b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c')

    def enumerate_serial(self):
        # Jade is not really an HID device, it shows as a serial/com port device.
        # Scan com ports looking for the relevant vid and pid, and use 'path' to
        # hold the path to the serial port device, eg. /dev/ttyUSB0
        devices = []
        for devinfo in list_ports.comports():
            device_product_key = (devinfo.vid, devinfo.pid)
            if device_product_key in self.DEVICE_IDS:
                device = Device(path=devinfo.device,
                                interface_number=-1,
                                id_=devinfo.serial_number,
                                product_key=device_product_key,
                                usage_page=-1,
                                transport_ui_string=devinfo.device)
                devices.append(device)

        # Maybe look for Jade Qemu simulator if the vars are set (experimental)
        if self.SIMULATOR_PATH is not None and self.SIMULATOR_TEST_SEED is not None:
            try:
                # If we can connect to a simulator and poke a seed in, add that too
                client = Jade_Client(self.SIMULATOR_PATH, plugin=self)
                device = Device(path=self.SIMULATOR_PATH,
                                interface_number=-1,
                                id_='Jade Qemu Simulator',
                                product_key=self.DEVICE_IDS[0],
                                usage_page=-1,
                                transport_ui_string='simulator')
                if client.jade.set_seed(self.SIMULATOR_TEST_SEED):
                    devices.append(device)
                client.close()
            except Exception as e:
                # If we get any sort of error do not add the simulator
                _logger.debug("Failed to connect to Jade simulator at {}".format(self.SIMULATOR_PATH))
                _logger.debug(e)

        return devices

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return

        # Register our own serial/com port scanning function
        self.device_manager().register_enumerate_func(self.enumerate_serial)

    def get_library_version(self):
        try:
            from . import jadepy
            version = jadepy.__version__
        except ImportError:
            raise
        except Exception:
            version = "unknown"
        return version

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        client = Jade_Client(device.path, plugin=self)

        # Check minimum supported firmware version
        if self.MIN_SUPPORTED_FW_VERSION > client.fwversion:
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'update using a Blockstream Green companion app')
                   .format(self.device, client.label()))
            self.logger.info(msg)

            if handler:
                handler.show_error(msg)

            raise OutdatedHwFirmwareException(msg)

        return client

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return

        path_suffix = wallet.get_address_index(address)
        if _is_multisig(wallet):
            # Multisig - wallet details must be registered on Jade hw
            multisig_name = _register_multisig_wallet(wallet, keystore, address)

            # Jade only needs the path suffix(es) and the multisig registration
            # name to generate the address, as the fixed derivation part is
            # embedded in the multisig wallet registration record
            # NOTE: all cosigners have same path suffix
            paths = [path_suffix] * wallet.n
            hw_address = keystore.show_address_multi(multisig_name, paths)
        else:
            # Single-sig/standard
            txin_type = wallet.get_txin_type(address)
            hw_address = keystore.show_address(path_suffix, txin_type)

        if hw_address != address:
            keystore.handler.show_error(_('The address generated by {} does not match!').format(self.device))

    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet=True) -> str:
        if new_wallet:
            return 'jade_start' if device_info.initialized else 'jade_not_initialized'
        else:
            return 'jade_unlock'

    # insert jade pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'jade_start': {
                'next': 'jade_xpub',
            },
            'jade_xpub': {
                'next': lambda d: wizard.wallet_password_view(d) if wizard.last_cosigner(d) else 'multisig_cosigner_keystore',
                'accept': wizard.maybe_master_pubkey,
                'last': lambda d: wizard.is_single_password() and wizard.last_cosigner(d)
            },
            'jade_not_initialized': {},
            'jade_unlock': {
                'last': True
            },
        }
        wizard.navmap_merge(views)
