# ----------------------------------------------------------------------------------
# Electrum plugin for the MIRkey by ellipticSecure
# https://ellipticsecure.com
#

import binascii
import os
import math
import logging
import ehsm

from electrum.plugin import Device
from electrum.crypto import sha256d
from electrum.bip32 import convert_bip32_path_to_list_of_uint32
from electrum import constants
from electrum.i18n import _
from electrum.keystore import Hardware_KeyStore
from ..hw_wallet import HW_PluginBase
from electrum.util import UserCancelled, UserFacingException
from electrum.base_wizard import HWD_SETUP_NEW_WALLET
from electrum.mnemonic import Mnemonic

from electrum.logging import get_logger


_logger = get_logger(__name__)
_logger.setLevel(logging.DEBUG)

ehsmlib = None

try:
    # if the shared lib is not in the system LD_LIBRARY_PATH then specify it in EHSM_MODULE
    if 'EHSM_MODULE' in os.environ:
        ehsmlib = ehsm.load_ehsm(os.environ['EHSM_MODULE'])
    else:
        ehsmlib = ehsm.load_ehsm()
except ImportError as e:
    pass


def b2hstr(s):
    return binascii.hexlify(s).decode('ascii')


class MIRKey_Client():

    def __init__(self, plugin, slot):
        self.slot = slot
        self.plugin = plugin
        self.opened = True
        self.password = None
        if 'EHSM_PIN' in os.environ:
            self.password = os.environ['EHSM_PIN'] # this is useful for hosted wallets
        self.isInitialized = False
        self.setupRunning = False

    def close(self):
        self.opened = False
        _logger.debug("Closing client")

    def timeout(self, cutoff):
        pass

    def label(self):
        return "MIRkey "+str(self.slot)

    def is_pairable(self):
        _logger.debug("is_pairable")
        return True

    def is_initialized(self):
        """Return true if the device has been initialized and has a user PIN set

        :return: true if the device has been initialized and has a user PIN set
        """
        ehsmlib.init()
        try:
            init = ehsmlib.is_user_pin_set(self.slot)
            major, minor = ehsmlib.fw_version(self.slot)
            if major < 1 or (major == 1 and minor < 13):
                raise RuntimeError("Please use the ellipticSecure Manager utility to update the device firmware.")
            return init
        except RuntimeError as re:
            raise RuntimeError("Failed to communicate with device: " + str(re))
        finally:
            ehsmlib.finalize()

    def has_root_key(self):
        """Returns true if the device has a root key.

        :return: true if root key found.
        """
        ehsmlib.init()
        try:
            session = ehsmlib.get_logged_in_rw_session(self.slot, self.password)
            found, handle = ehsmlib.bip32_has_root_key(session)
            _logger.debug(f"Has root key: {found}")
            return found
        except RuntimeError:
            self.password = None
        finally:
            ehsmlib.finalize()

    def is_paired(self):
        _logger.debug("is_paired")
        return self.is_initialized() and self.password is not None

    def has_usable_connection_with_device(self):
        # called by DeviceMgr during scan - we have a usable connection if library is loaded
        return True

    def sign_hash(self, hash, indexes):
        """Sign a hash with key at the index path specified by indexes

        :param hash: hash (32 bytes) to sign
        :param indexes: derivation path
        :return: the asn1 encoded signature
        """
        ehsmlib.init()
        try:
            session = ehsmlib.get_logged_in_rw_session(self.slot, self.password)
            return ehsmlib.bip32_sign_data(session, hash, indexes)
        finally:
            ehsmlib.finalize()

    def get_xpub(self, bip32_path, xtype):
        # called by plugin
        _logger.debug("Get xpub")
        assert xtype in self.plugin.SUPPORTED_XTYPES

        msg = _("Enter your device user PIN:")
        while self.password is None:
            if not self.password_dialog(msg):
                raise UserCancelled()

        indexes = convert_bip32_path_to_list_of_uint32(bip32_path)
        ehsmlib.init()
        try:
            session = ehsmlib.get_logged_in_rw_session(self.slot, self.password)
            return ehsmlib.bip32_get_xpub(session, indexes, constants.net.XPUB_HEADERS[xtype])
        except RuntimeError:
            self.password = None
        finally:
            ehsmlib.finalize()

    def password_dialog(self, msg):
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False
            if len(password) < 4:
                msg = _("PIN must be at least 4 characters.") + \
                      "\n\n" + _("Enter password:")
            else:
                self.password = password.encode('utf8')
                return True

    def check_device_dialog(self, wizard):
        _logger.debug("Check device dialog")

        if not self.is_initialized():
            msg = _("The MIRkey has not been initialized.") + " " + \
                  _("Please use the ellipticSecure Manager to initialize the device and set a user PIN.") + "\n\n"
            self.handler.show_error(msg)
            return False

        # Get PIN from user
        msg = _("Enter your device user PIN:")
        while self.password is None:
            if not self.password_dialog(msg):
                raise UserCancelled()

        if not self.has_root_key():
            self.seed_device_dialog(wizard)
        else:
            self.recover_or_erase_dialog(wizard)

        return self.isInitialized

    def _destroy_current_key(self):
        ehsmlib.init()
        try:
            session = ehsmlib.get_logged_in_rw_session(self.slot, self.password)
            found, handle = ehsmlib.bip32_has_root_key(session)
            if found:
                ehsmlib.destroy_object(session, handle)
        except RuntimeError:
            self.password = None
        finally:
            ehsmlib.finalize()

    def recover_or_erase_dialog(self, wizard):
        msg = _("The device already contains a Bitcoin root key. Choose an option:") + "\n"
        choices = [
            (_("Recover a wallet using the current key")),
            (_("Erase the current Bitcoin root key"))
        ]
        try:
            reply = self.handler.win.query_choice(msg, choices)
        except Exception:
            return  # Back
        if reply == 1:
            msg = _("Delete current root key. Are you really sure?") + "\n"
            choices = [
                (_("No")),
                (_("Yes, delete the key"))
            ]
            try:
                reply = self.handler.win.query_choice(msg, choices)
            except Exception:
                return  # Back

            if reply == 0:
                self.isInitialized = False
                raise UserFacingException(_("Device setup cancelled."))
            if reply == 1:
                self._destroy_current_key()
                self.seed_device_dialog(wizard)
        else:
            # Use existing key
            self.isInitialized = True

    @staticmethod
    def is_valid_seed(seed):
        return True

    def seed_device_dialog(self, wizard):
        _logger.debug("Seed device dialog")

        msg = _("Choose how to initialize your device wallet:") + "\n"
        choices = [
            (_("Import from a seed")),
            (_("Generate a new random seed"))
        ]
        try:
            reply = self.handler.win.query_choice(msg, choices)
        except Exception:
            return  # Back

        if reply == 1:
            choices = [
                ('_create_segwit', _('Segwit')),
                ('_create_standard', _('Legacy')),
            ]
            wizard.choose_seed_type(choices=choices)
        else:
            wizard.opt_bip39 = False
            wizard.opt_ext = False
            f = lambda seed, is_bip39, is_ext: wizard.run('on_restore_seed', self, seed, is_ext)
            wizard.restore_seed_dialog(run_next=f, test=self.is_valid_seed)
            self.isInitialized = True

    def import_key(self, seed):
        _logger.debug("Import key")
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, "")
        ehsmlib.init()
        try:
            session = ehsmlib.get_logged_in_rw_session(self.slot, self.password)
            ehsmlib.bip32_import_root_key(session, bip32_seed)
        finally:
            ehsmlib.finalize()

    def confirm_seed_dialog(self, wizard, test):
        options = []
        if wizard.opt_ext:
            options.append('ext')
        if wizard.opt_bip39:
            options.append('bip39')
        title = _('Confirm Seed')
        message = _('Please enter your seed phrase to confirm it.')
        return wizard.seed_input(title, message, test, options)

    def create_seed(self, wizard, seed_type):
        # called from plugin by wizard
        from electrum import mnemonic
        seed = mnemonic.Mnemonic('en').make_seed(seed_type)
        wizard.opt_bip39 = False
        wizard.opt_ext = False
        f = lambda x: self._confirm_seed(wizard, seed)
        wizard.show_seed_dialog(run_next=f, seed_text=seed)

    def _confirm_seed(self, wizard, seed):
        seed_confirm = self.confirm_seed_dialog(wizard, test=self.is_valid_seed)
        if seed_confirm[0] == seed:
            self.import_key(seed)
            self.isInitialized = True
        else:
            raise UserFacingException(_("Seeds did not match."))


class MIRkey_KeyStore(Hardware_KeyStore):
    hw_type = 'mirkey'
    device = 'MIRkey'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        self.force_watching_only = False
        self.maxInputs = 14  # maximum inputs per single sign command
        _logger.debug("Keystore init")

    def get_derivation(self):
        return str(self.derivation)

    def is_p2pkh(self):
        return self.derivation.startswith("m/44'/")

    def raise_error(self, message, clear_client=False):
        if clear_client:
            self.client = None
        raise Exception(message)

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Encryption and decryption are currently not supported for {}').format(self.device))

    def sign_message(self, sequence, message, password):
        _logger.debug("Signing message")
        raise RuntimeError(_('Message signing is currently not supported for {}').format(self.device))

    def sign_transaction(self, tx, password):
        _logger.debug("Signing transaction")

        if tx.is_complete():
            return

        try:
            derivations = self.get_tx_derivations(tx)
            hasharray = []

            for i, txin in enumerate(tx.inputs()):
                for x_pubkey in txin['x_pubkeys']:
                    if x_pubkey in derivations:
                        index = derivations.get(x_pubkey)
                        inputPath = "%s/%d/%d" % (self.get_derivation(), index[0], index[1])
                        inputHash = sha256d(binascii.unhexlify(tx.serialize_preimage(i)))
                        hasharray_i = {'hash': b2hstr(inputHash), 'keypath': inputPath}
                        hasharray.append(hasharray_i)
                        break

            sigs = []
            steps = math.ceil(1.0 * len(hasharray) / self.maxInputs)
            for step in range(int(steps)):
                hashes = hasharray[step * self.maxInputs : (step + 1) * self.maxInputs]
                client = self.plugin.get_client(self)
                sig = client.sign_hash(binascii.unhexlify(hashes[0]["hash"]), convert_bip32_path_to_list_of_uint32(hashes[0]["keypath"]))
                sigs.append(sig)

            for i, txin in enumerate(tx.inputs()):
                num = txin['num_sig']
                for pubkey in txin['pubkeys']:
                    signatures = list(filter(None, txin['signatures']))
                    if len(signatures) == num:
                        break  # txin is complete
                    ii = txin['pubkeys'].index(pubkey)
                    sig = b2hstr(sigs[i]) + '01'
                    tx.add_signature_to_txin(i, ii, sig)
        except UserCancelled:
            raise
        except BaseException as e:
            self.raise_error(e, True)
        else:
            _logger.info("Transaction is_complete {tx.is_complete()}")
            tx.raw = tx.serialize()


class MIRkeyPlugin(HW_PluginBase):

    keystore_class = MIRkey_KeyStore
    client = None
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
    DEVICE_IDS = ("MIRkey")

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        if ehsmlib is not None:
            self.libraries_available = True  # required base plugin property
            self.device_manager().register_enumerate_func(self.enumerate)

        self.mirkey_config = self.config.get('mirkey', {})

    def enumerate(self):

        _logger.debug("Enumerating devices")
        slots = ehsmlib.enumerate_slots()
        return [Device(path="path",
                       interface_number=slot,
                       id_=str(slot),
                       product_key="MIRkey",
                       usage_page=0,
                       transport_ui_string=str(slot))
                for slot in slots]

    def create_client(self, device, handler):
        if handler:
            self.handler = handler
        _logger.debug("Creating client")
        return MIRKey_Client(self, device.interface_number)

    def setup_device(self, device_info, wizard, purpose):
        _logger.debug("Setting up MIRkey device")
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise Exception(_('Failed to create a client for this device.'))
        client.handler = self.create_handler(wizard)
        if purpose == HWD_SETUP_NEW_WALLET:
            client.setupRunning = True

    def get_xpub(self, device_id, derivation, xtype, wizard):
        _logger.debug("Getting xpub: "+xtype)
        devmgr = self.device_manager()
        self.client = devmgr.client_by_id(device_id)
        self.client.handler = self.create_handler(wizard)
        if self.client.check_device_dialog(wizard):
            xpub = self.client.get_xpub(derivation, xtype)
            return xpub
        else:
            raise UserFacingException(_("Device not ready"))

    def on_restore_seed(self, wizard, client, seed, is_ext):
        _logger.debug("Restoring from seed")
        client.import_key(seed)

    def get_client(self, keystore, force_pair=True):
        _logger.debug("Getting client: ")
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        return client

    # called by wizard during seed_device_dialog
    def _create_segwit(self, wizard): self.client.create_seed(wizard, 'segwit')
    # called by wizard during seed_device_dialog
    def _create_standard(self, wizard): self.client.create_seed(wizard, 'standard')
