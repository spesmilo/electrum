#
# Coldcard Electrum plugin main code.
#
#
import os
import time
from typing import TYPE_CHECKING, Optional
import struct

from electrum import bip32
from electrum.bip32 import BIP32Node, InvalidMasterKeyVersionBytes
from electrum.i18n import _
from electrum.plugin import Device, hook, runs_in_hwd_thread
from electrum.keystore import Hardware_KeyStore, KeyStoreWithMPK
from electrum.transaction import PartialTransaction
from electrum.wallet import Standard_Wallet, Multisig_Wallet, Abstract_Wallet
from electrum.util import bfh, versiontuple, UserFacingException
from electrum.logging import get_logger

from electrum.hw_wallet import HW_PluginBase, HardwareClientBase
from electrum.hw_wallet.plugin import LibraryFoundButUnusable, only_hook_if_libraries_available

if TYPE_CHECKING:
    from electrum.plugin import DeviceInfo
    from electrum.wizard import NewWalletWizard

_logger = get_logger(__name__)


try:
    import hid
    from ckcc.protocol import CCProtocolPacker, CCProtocolUnpacker
    from ckcc.protocol import CCProtoError, CCUserRefused, CCBusyError
    from ckcc.constants import (MAX_MSG_LEN, MAX_BLK_LEN, MSG_SIGNING_MAX_LENGTH, MAX_TXN_LEN,
        AF_CLASSIC, AF_P2SH, AF_P2WPKH, AF_P2WSH, AF_P2WPKH_P2SH, AF_P2WSH_P2SH)

    from ckcc.client import ColdcardDevice, COINKITE_VID, CKCC_PID, CKCC_SIMULATOR_PATH

    requirements_ok = True


    class ElectrumColdcardDevice(ColdcardDevice):
        # avoid use of pycoin for MiTM message signature test
        def mitm_verify(self, sig, expect_xpub):
            # verify a signature (65 bytes) over the session key, using the master bip32 node
            # - customized to use specific EC library of Electrum.
            pubkey = BIP32Node.from_xkey(expect_xpub).eckey
            return pubkey.ecdsa_verify(sig[1:65], self.session_key)

except ImportError as e:
    if not (isinstance(e, ModuleNotFoundError) and e.name == 'ckcc'):
        _logger.exception('error importing coldcard plugin deps')
    requirements_ok = False

    COINKITE_VID = 0xd13e
    CKCC_PID     = 0xcc10

CKCC_SIMULATED_PID = CKCC_PID ^ 0x55aa


class CKCCClient(HardwareClientBase):
    def __init__(self, plugin, handler, dev_path, *, is_simulator=False):
        HardwareClientBase.__init__(self, plugin=plugin)
        self.device = plugin.device
        self.handler = handler

        # if we know what the (xfp, xpub) "should be" then track it here
        self._expected_device = None

        if is_simulator:
            self.dev = ElectrumColdcardDevice(dev_path, encrypt=True)
        else:
            # open the real HID device
            hd = hid.device(path=dev_path)
            hd.open_path(dev_path)

            self.dev = ElectrumColdcardDevice(dev=hd, encrypt=True)

        # NOTE: MiTM test is delayed until we have a hint as to what XPUB we
        # should expect. It's also kinda slow.

    def device_model_name(self) -> Optional[str]:
        return 'Coldcard'

    def get_soft_device_id(self) -> Optional[str]:
        try:
            super().get_soft_device_id()
        except CCProtoError:
            return None

    def __repr__(self):
        return '<CKCCClient: xfp=%s label=%r>' % (xfp2str(self.dev.master_fingerprint),
                                                        self.label())

    @runs_in_hwd_thread
    def verify_connection(self, expected_xfp: int, expected_xpub: str):
        ex = (expected_xfp, expected_xpub)

        if self._expected_device == ex:
            # all is as expected
            return

        assert expected_xpub

        if ((self._expected_device is not None)
                or (self.dev.master_fingerprint != expected_xfp)
                or (self.dev.master_xpub != expected_xpub)):
            # probably indicating programming error, not hacking
            _logger.info(f"xpubs. reported by device: {self.dev.master_xpub}. "
                         f"stored in file: {expected_xpub}")
            raise RuntimeError("Expecting %s but that's not what's connected?!" %
                               xfp2str(expected_xfp))

        # check signature over session key
        # - mitm might have lied about xfp and xpub up to here
        # - important that we use value capture at wallet creation time, not some value
        #   we read over USB today
        self.dev.check_mitm(expected_xpub=expected_xpub)

        self._expected_device = ex

        _logger.info("Successfully verified against MiTM")

    def is_pairable(self):
        # can't do anything w/ devices that aren't setup (this code not normally reachable)
        return bool(self.dev.master_xpub)

    @runs_in_hwd_thread
    def close(self):
        # close the HID device (so can be reused)
        self.dev.close()
        self.dev = None

    def is_initialized(self):
        return bool(self.dev.master_xpub)

    def label(self):
        # 'label' of this Coldcard. Warning: gets saved into wallet file, which might
        # not be encrypted, so better for privacy if based on xpub/fingerprint rather than
        # USB serial number.
        if self.dev.is_simulator:
            lab = 'Coldcard Simulator ' + xfp2str(self.dev.master_fingerprint)
        elif not self.dev.master_fingerprint:
            # failback; not expected
            lab = 'Coldcard #' + self.dev.serial
        else:
            lab = 'Coldcard ' + xfp2str(self.dev.master_fingerprint)

        return lab

    def _get_ckcc_master_xpub_from_device(self):
        master_xpub = self.dev.master_xpub
        if master_xpub is not None:
            try:
                node = BIP32Node.from_xkey(master_xpub)
            except InvalidMasterKeyVersionBytes:
                raise UserFacingException(
                    _('Invalid xpub magic. Make sure your {} device is set to the correct chain.').format(self.device) + ' ' +
                    _('You might have to unplug and plug it in again.')
                ) from None
            return master_xpub

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        # Do end-to-end ping test
        try:
            self.ping_check()
            return True
        except Exception:
            return False

    @runs_in_hwd_thread
    def get_xpub(self, bip32_path, xtype):
        assert xtype in ColdcardPlugin.SUPPORTED_XTYPES
        _logger.info('Derive xtype = %r' % xtype)
        xpub = self.dev.send_recv(CCProtocolPacker.get_xpub(bip32_path), timeout=5000)
        # TODO handle timeout?
        # change type of xpub to the requested type
        try:
            node = BIP32Node.from_xkey(xpub)
        except InvalidMasterKeyVersionBytes:
            raise UserFacingException(_('Invalid xpub magic. Make sure your {} device is set to the correct chain.')
                                      .format(self.device)) from None
        if xtype != 'standard':
            xpub = node._replace(xtype=xtype).to_xpub()
        return xpub

    @runs_in_hwd_thread
    def ping_check(self):
        # check connection is working
        assert self.dev.session_key, 'not encrypted?'
        req = b'1234 Electrum Plugin 4321'      # free up to 59 bytes
        try:
            echo = self.dev.send_recv(CCProtocolPacker.ping(req))
            assert echo == req
        except Exception:
            raise RuntimeError("Communication trouble with Coldcard")

    @runs_in_hwd_thread
    def show_address(self, path, addr_fmt):
        # prompt user w/ address, also returns it immediately.
        return self.dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    @runs_in_hwd_thread
    def show_p2sh_address(self, *args, **kws):
        # prompt user w/ p2sh address, also returns it immediately.
        return self.dev.send_recv(CCProtocolPacker.show_p2sh_address(*args, **kws), timeout=None)

    @runs_in_hwd_thread
    def get_version(self):
        # gives list of strings
        return self.dev.send_recv(CCProtocolPacker.version(), timeout=1000).split('\n')

    @runs_in_hwd_thread
    def sign_message_start(self, path, msg, addr_fmt):
        # this starts the UX experience.
        self.dev.send_recv(CCProtocolPacker.sign_message(msg, path, addr_fmt), timeout=None)

    @runs_in_hwd_thread
    def sign_message_poll(self):
        # poll device... if user has approved, will get tuple: (addr, sig) else None
        return self.dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)

    @runs_in_hwd_thread
    def sign_transaction_start(self, raw_psbt: bytes, *, finalize: bool = False):
        # Multiple steps to sign:
        # - upload binary
        # - start signing UX
        # - wait for coldcard to complete process, or have it refused.
        # - download resulting txn
        assert 20 <= len(raw_psbt) < MAX_TXN_LEN, 'PSBT is too big'
        dlen, chk = self.dev.upload_file(raw_psbt)

        resp = self.dev.send_recv(CCProtocolPacker.sign_transaction(dlen, chk, finalize=finalize),
                                    timeout=None)

        if resp is not None:
            raise ValueError(resp)

    @runs_in_hwd_thread
    def sign_transaction_poll(self):
        # poll device... if user has approved, will get tuple: (length, checksum) else None
        return self.dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)

    @runs_in_hwd_thread
    def download_file(self, length, checksum, file_number=1):
        # get a file
        return self.dev.download_file(length, checksum, file_number=file_number)



class Coldcard_KeyStore(Hardware_KeyStore):
    hw_type = 'coldcard'
    device = 'Coldcard'

    plugin: 'ColdcardPlugin'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        self.ux_busy = False

        # we need to know at least the fingerprint of the master xpub to verify against MiTM
        # - device reports these value during encryption setup process
        # - full xpub value now optional
        self.ckcc_xpub = d.get('ckcc_xpub', None)

    def dump(self):
        # our additions to the stored data about keystore -- only during creation?
        d = Hardware_KeyStore.dump(self)
        d['ckcc_xpub'] = self.ckcc_xpub
        return d

    def get_xfp_int(self) -> int:
        xfp = self.get_root_fingerprint()
        assert xfp is not None
        return xfp_int_from_xfp_bytes(bfh(xfp))

    def opportunistically_fill_in_missing_info_from_device(self, client: 'CKCCClient'):
        super().opportunistically_fill_in_missing_info_from_device(client)
        if self.ckcc_xpub is None:
            self.ckcc_xpub = client._get_ckcc_master_xpub_from_device()
            self.is_requesting_to_be_rewritten_to_wallet_file = True

    def get_client(self, *args, **kwargs):
        # called when user tries to do something like view address, sign something.
        # - not called during probing/setup
        # - will fail if indicated device can't produce the xpub (at derivation) expected
        client = super().get_client(*args, **kwargs)  # type: Optional[CKCCClient]
        if client:
            xfp_int = self.get_xfp_int()
            client.verify_connection(xfp_int, self.ckcc_xpub)

        return client

    def give_error(self, message):
        self.logger.info(message)
        if not self.ux_busy:
            self.handler.show_error(message)
        else:
            self.ux_busy = False
        raise UserFacingException(message)

    def wrap_busy(func):
        # decorator: function takes over the UX on the device.
        def wrapper(self, *args, **kwargs):
            try:
                self.ux_busy = True
                return func(self, *args, **kwargs)
            finally:
                self.ux_busy = False
        return wrapper

    def decrypt_message(self, pubkey, message, password):
        raise UserFacingException(_('Encryption and decryption are currently not supported for {}').format(self.device))

    @wrap_busy
    def sign_message(self, sequence, message, password, *, script_type=None):
        # Sign a message on device. Since we have big screen, of course we
        # have to show the message unabiguously there first!
        try:
            msg = message.encode('ascii', errors='strict')
            assert 1 <= len(msg) <= MSG_SIGNING_MAX_LENGTH
        except (UnicodeError, AssertionError):
            # there are other restrictions on message content,
            # but let the device enforce and report those
            self.handler.show_error('Only short (%d max) ASCII messages can be signed.'
                                            % MSG_SIGNING_MAX_LENGTH)
            return b''

        path = self.get_derivation_prefix() + ("/%d/%d" % sequence)

        if script_type:
            addr_fmt = self._encode_txin_type(script_type)
        else:
            addr_fmt = AF_CLASSIC

        try:
            cl = self.get_client()
            try:
                self.handler.show_message("Signing message (using %s)..." % path)

                cl.sign_message_start(path, msg, addr_fmt)

                while 1:
                    # How to kill some time, without locking UI?
                    time.sleep(0.250)

                    resp = cl.sign_message_poll()
                    if resp is not None:
                        break

            finally:
                self.handler.finished()

            assert len(resp) == 2
            addr, raw_sig = resp

            # already encoded in Bitcoin fashion, binary.
            assert 40 < len(raw_sig) <= 65

            return raw_sig

        except (CCUserRefused, CCBusyError) as exc:
            self.handler.show_error(str(exc))
        except CCProtoError as exc:
            self.logger.exception('Error showing address')
            self.handler.show_error('{}\n\n{}'.format(
                _('Error showing address') + ':', str(exc)))
        except Exception as e:
            self.give_error(e)

        # give empty bytes for error cases; it seems to clear the old signature box
        return b''

    @wrap_busy
    def sign_transaction(self, tx, password):
        # Upload PSBT for signing.
        # - we can also work offline (without paired device present)
        if tx.is_complete():
            return

        client = self.get_client()

        assert client.dev.master_fingerprint == self.get_xfp_int()

        raw_psbt = tx.serialize_as_bytes()

        try:
            try:
                self.handler.show_message("Authorize Transaction...")

                client.sign_transaction_start(raw_psbt)

                while 1:
                    # How to kill some time, without locking UI?
                    time.sleep(0.250)

                    resp = client.sign_transaction_poll()
                    if resp is not None:
                        break

                rlen, rsha = resp

                # download the resulting txn.
                raw_resp = client.download_file(rlen, rsha)

            finally:
                self.handler.finished()

        except (CCUserRefused, CCBusyError) as exc:
            self.logger.info(f'Did not sign: {exc}')
            self.handler.show_error(str(exc))
            return
        except BaseException as e:
            self.logger.exception('')
            self.give_error(e)
            return

        tx2 = PartialTransaction.from_raw_psbt(raw_resp)
        # apply partial signatures back into txn
        tx.combine_with_other_psbt(tx2)
        # caller's logic looks at tx now and if it's sufficiently signed,
        # will send it if that's the user's intent.

    @staticmethod
    def _encode_txin_type(txin_type):
        # Map from Electrum code names to our code numbers.
        return {'standard': AF_CLASSIC, 'p2pkh': AF_CLASSIC,
                'p2sh': AF_P2SH,
                'p2wpkh-p2sh': AF_P2WPKH_P2SH,
                'p2wpkh': AF_P2WPKH,
                'p2wsh-p2sh': AF_P2WSH_P2SH,
                'p2wsh': AF_P2WSH,
                }[txin_type]

    @wrap_busy
    def show_address(self, sequence, txin_type):
        client = self.get_client()
        address_path = self.get_derivation_prefix()[2:] + "/%d/%d"%sequence
        addr_fmt = self._encode_txin_type(txin_type)
        try:
            try:
                self.handler.show_message(_("Showing address ..."))
                dev_addr = client.show_address(address_path, addr_fmt)
                # we could double check address here
            finally:
                self.handler.finished()
        except CCProtoError as exc:
            self.logger.exception('Error showing address')
            self.handler.show_error('{}\n\n{}'.format(
                _('Error showing address') + ':', str(exc)))
        except BaseException as exc:
            self.logger.exception('')
            self.handler.show_error(exc)

    @wrap_busy
    def show_p2sh_address(self, M, script, xfp_paths, txin_type):
        client = self.get_client()
        addr_fmt = self._encode_txin_type(txin_type)
        try:
            try:
                self.handler.show_message(_("Showing address ..."))
                dev_addr = client.show_p2sh_address(M, xfp_paths, script, addr_fmt=addr_fmt)
                # we could double check address here
            finally:
                self.handler.finished()
        except CCProtoError as exc:
            self.logger.exception('Error showing address')
            self.handler.show_error('{}.\n{}\n\n{}'.format(
                _('Error showing address'),
                _('Make sure you have imported the correct wallet description '
                  'file on the device for this multisig wallet.'),
                str(exc)))
        except BaseException as exc:
            self.logger.exception('')
            self.handler.show_error(exc)


class ColdcardPlugin(HW_PluginBase):
    keystore_class = Coldcard_KeyStore
    minimum_library = (0, 7, 7)

    DEVICE_IDS = [
        (COINKITE_VID, CKCC_PID),
        (COINKITE_VID, CKCC_SIMULATED_PID)
    ]

    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return

        self.device_manager().register_devices(self.DEVICE_IDS, plugin=self)
        self.device_manager().register_enumerate_func(self.detect_simulator)

    def get_library_version(self):
        import ckcc
        try:
            version = ckcc.__version__
        except AttributeError:
            version = 'unknown'
        if requirements_ok:
            return version
        else:
            raise LibraryFoundButUnusable(library_version=version)

    def detect_simulator(self):
        # if there is a simulator running on this machine,
        # return details about it so it's offered as a pairing choice
        fn = CKCC_SIMULATOR_PATH

        if os.path.exists(fn):
            return [Device(path=fn,
                           interface_number=-1,
                           id_=fn,
                           product_key=(COINKITE_VID, CKCC_SIMULATED_PID),
                           usage_page=0,
                           transport_ui_string='simulator')]

        return []

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        # We are given a HID device, or at least some details about it.
        # Not sure why not we aren't just given a HID library handle, but
        # the 'path' is unabiguous, so we'll use that.
        try:
            rv = CKCCClient(self, handler, device.path,
                            is_simulator=(device.product_key[1] == CKCC_SIMULATED_PID))
            return rv
        except Exception as e:
            self.logger.exception('late failure connecting to device?')
            return None

    @runs_in_hwd_thread
    def get_client(self, keystore, force_pair=True, *,
                   devices=None, allow_user_interaction=True) -> Optional['CKCCClient']:
        # Acquire a connection to the hardware device (via USB)
        client = super().get_client(keystore, force_pair,
                                    devices=devices,
                                    allow_user_interaction=allow_user_interaction)

        if client is not None:
            client.ping_check()

        return client

    @staticmethod
    def export_ms_wallet(wallet: Multisig_Wallet, fp, name):
        # Build the text file Coldcard needs to understand the multisig wallet
        # it is participating in. All involved Coldcards can share same file.
        assert isinstance(wallet, Multisig_Wallet)

        print('# Exported from Electrum', file=fp)
        print(f'Name: {name:.20s}', file=fp)
        print(f'Policy: {wallet.m} of {wallet.n}', file=fp)
        print(f'Format: {wallet.txin_type.upper()}', file=fp)

        xpubs = []
        for xpub, ks in zip(wallet.get_master_public_keys(), wallet.get_keystores()):  # type: str, KeyStoreWithMPK
            fp_bytes, der_full = ks.get_fp_and_derivation_to_be_used_in_partial_tx(der_suffix=[], only_der_suffix=False)
            fp_hex = fp_bytes.hex().upper()
            der_prefix_str = bip32.convert_bip32_intpath_to_strpath(der_full)
            xpubs.append((fp_hex, xpub, der_prefix_str))

        # Before v3.2.1 derivation didn't matter too much to the Coldcard, since it
        # could use key path data from PSBT or USB request as needed. However,
        # derivation data is now required.

        print('', file=fp)

        assert len(xpubs) == wallet.n
        for xfp, xpub, der_prefix in xpubs:
            print(f'Derivation: {der_prefix}', file=fp)
            print(f'{xfp}: {xpub}\n', file=fp)

    def show_address(self, wallet, address, keystore: 'Coldcard_KeyStore' = None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return

        txin_type = wallet.get_txin_type(address)

        # Standard_Wallet => not multisig, must be bip32
        if type(wallet) is Standard_Wallet:
            sequence = wallet.get_address_index(address)
            keystore.show_address(sequence, txin_type)
        elif type(wallet) is Multisig_Wallet:
            assert isinstance(wallet, Multisig_Wallet)  # only here for type-hints in IDE
            # More involved for P2SH/P2WSH addresses: need M, and all public keys, and their
            # derivation paths. Must construct script, and track fingerprints+paths for
            # all those keys

            pubkey_deriv_info = wallet.get_public_keys_with_deriv_info(address)
            pubkey_hexes = sorted([pk.hex() for pk in list(pubkey_deriv_info)])
            xfp_paths = []
            for pubkey_hex in pubkey_hexes:
                pubkey = bytes.fromhex(pubkey_hex)
                ks, der_suffix = pubkey_deriv_info[pubkey]
                fp_bytes, der_full = ks.get_fp_and_derivation_to_be_used_in_partial_tx(der_suffix, only_der_suffix=False)
                xfp_int = xfp_int_from_xfp_bytes(fp_bytes)
                xfp_paths.append([xfp_int] + list(der_full))

            script = wallet.pubkeys_to_scriptcode(pubkey_hexes)

            keystore.show_p2sh_address(wallet.m, script, xfp_paths, txin_type)

        else:
            keystore.handler.show_error(_('This function is only available for standard wallets when using {}.').format(self.device))
            return

    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet=True) -> str:
        if new_wallet:
            return 'coldcard_start' if device_info.initialized else 'coldcard_not_initialized'
        else:
            return 'coldcard_unlock'

    # insert coldcard pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'coldcard_start': {
                'next': 'coldcard_xpub',
            },
            'coldcard_xpub': {
                'next': lambda d: wizard.wallet_password_view(d) if wizard.last_cosigner(d) else 'multisig_cosigner_keystore',
                'accept': wizard.maybe_master_pubkey,
                'last': lambda d: wizard.is_single_password() and wizard.last_cosigner(d)
            },
            'coldcard_not_initialized': {},
            'coldcard_unlock': {
                'last': True
            },
        }
        wizard.navmap_merge(views)


def xfp_int_from_xfp_bytes(fp_bytes: bytes) -> int:
    return int.from_bytes(fp_bytes, byteorder="little", signed=False)


def xfp2str(xfp: int) -> str:
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return struct.pack('<I', xfp).hex().lower()

# EOF
