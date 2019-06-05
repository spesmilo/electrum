#
# Coldcard Electrum plugin main code.
#
#
from struct import pack, unpack
import os, sys, time, io
import traceback

from electrum.bip32 import BIP32Node, InvalidMasterKeyVersionBytes
from electrum.i18n import _
from electrum.plugin import Device
from electrum.keystore import Hardware_KeyStore, xpubkey_to_pubkey, Xpub
from electrum.transaction import Transaction
from electrum.wallet import Standard_Wallet
from electrum.crypto import hash_160
from electrum.util import bfh, bh2u, versiontuple, UserFacingException
from electrum.base_wizard import ScriptTypeNotSupported
from electrum.logging import get_logger

from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import LibraryFoundButUnusable


_logger = get_logger(__name__)


try:
    import hid
    from ckcc.protocol import CCProtocolPacker, CCProtocolUnpacker
    from ckcc.protocol import CCProtoError, CCUserRefused, CCBusyError
    from ckcc.constants import (MAX_MSG_LEN, MAX_BLK_LEN, MSG_SIGNING_MAX_LENGTH, MAX_TXN_LEN,
        AF_CLASSIC, AF_P2SH, AF_P2WPKH, AF_P2WSH, AF_P2WPKH_P2SH, AF_P2WSH_P2SH)
    from ckcc.constants import (
        PSBT_GLOBAL_UNSIGNED_TX, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO,
        PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT,
        PSBT_IN_BIP32_DERIVATION, PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_REDEEM_SCRIPT)

    from ckcc.client import ColdcardDevice, COINKITE_VID, CKCC_PID, CKCC_SIMULATOR_PATH

    requirements_ok = True


    class ElectrumColdcardDevice(ColdcardDevice):
        # avoid use of pycoin for MiTM message signature test
        def mitm_verify(self, sig, expect_xpub):
            # verify a signature (65 bytes) over the session key, using the master bip32 node
            # - customized to use specific EC library of Electrum.
            pubkey = BIP32Node.from_xkey(expect_xpub).eckey
            try:
                pubkey.verify_message_hash(sig[1:65], self.session_key)
                return True
            except:
                return False

except ImportError:
    requirements_ok = False

    COINKITE_VID = 0xd13e
    CKCC_PID     = 0xcc10

CKCC_SIMULATED_PID = CKCC_PID ^ 0x55aa

def my_var_int(l):
    # Bitcoin serialization of integers... directly into binary!
    if l < 253:
        return pack("B", l)
    elif l < 0x10000:
        return pack("<BH", 253, l)
    elif l < 0x100000000:
        return pack("<BI", 254, l)
    else:
        return pack("<BQ", 255, l)

def xfp_from_xpub(xpub):
    # sometime we need to BIP32 fingerprint value: 4 bytes of ripemd(sha256(pubkey))
    # UNTESTED
    kk = bfh(Xpub.get_pubkey_from_xpub(xpub, []))
    assert len(kk) == 33
    xfp, = unpack('<I', hash_160(kk)[0:4])
    return xfp


class CKCCClient:
    # Challenge: I haven't found anywhere that defines a base class for this 'client',
    # nor an API (interface) to be met. Winging it. Gets called from lib/plugins.py mostly?

    def __init__(self, plugin, handler, dev_path, is_simulator=False):
        self.device = plugin.device
        self.handler = handler

        # if we know what the (xfp, xpub) "should be" then track it here
        self._expected_device = None

        if is_simulator:
            self.dev = ElectrumColdcardDevice(dev_path, encrypt=True)
        else:
            # open the real HID device
            import hid
            hd = hid.device(path=dev_path)
            hd.open_path(dev_path)

            self.dev = ElectrumColdcardDevice(dev=hd, encrypt=True)

        # NOTE: MiTM test is delayed until we have a hint as to what XPUB we
        # should expect. It's also kinda slow.

    def __repr__(self):
        return '<CKCCClient: xfp=%08x label=%r>' % (self.dev.master_fingerprint,
                                                        self.label())

    def verify_connection(self, expected_xfp, expected_xpub):
        ex = (expected_xfp, expected_xpub)

        if self._expected_device == ex:
            # all is as expected
            return

        if ( (self._expected_device is not None) 
                or (self.dev.master_fingerprint != expected_xfp)
                or (self.dev.master_xpub != expected_xpub)):
            # probably indicating programing error, not hacking
            _logger.info(f"xpubs. reported by device: {self.dev.master_xpub}. "
                         f"stored in file: {expected_xpub}")
            raise RuntimeError("Expecting 0x%08x but that's not what's connected?!" %
                               expected_xfp)

        # check signature over session key
        # - mitm might have lied about xfp and xpub up to here
        # - important that we use value capture at wallet creation time, not some value
        #   we read over USB today
        self.dev.check_mitm(expected_xpub=expected_xpub)

        self._expected_device = ex

        _logger.info("Successfully verified against MiTM")

    def is_pairable(self):
        # can't do anything w/ devices that aren't setup (but not normally reachable)
        return bool(self.dev.master_xpub)

    def timeout(self, cutoff):
        # nothing to do?
        pass

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
            lab = 'Coldcard Simulator 0x%08x' % self.dev.master_fingerprint
        elif not self.dev.master_fingerprint:
            # failback; not expected
            lab = 'Coldcard #' + self.dev.serial
        else:
            lab = 'Coldcard 0x%08x' % self.dev.master_fingerprint

        # Hack zone: during initial setup I need the xfp and master xpub but 
        # very few objects are passed between the various steps of base_wizard.
        # Solution: return a string with some hidden metadata
        # - see <https://stackoverflow.com/questions/7172772/abc-for-string>
        # - needs to work w/ deepcopy
        class LabelStr(str):
            def __new__(cls, s, xfp=None, xpub=None):
                self = super().__new__(cls, str(s))
                self.xfp = getattr(s, 'xfp', xfp)
                self.xpub = getattr(s, 'xpub', xpub)
                return self

        return LabelStr(lab, self.dev.master_fingerprint, self.dev.master_xpub)

    def has_usable_connection_with_device(self):
        # Do end-to-end ping test
        try:
            self.ping_check()
            return True
        except:
            return False

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

    def ping_check(self):
        # check connection is working
        assert self.dev.session_key, 'not encrypted?'
        req = b'1234 Electrum Plugin 4321'      # free up to 59 bytes
        try:
            echo = self.dev.send_recv(CCProtocolPacker.ping(req))
            assert echo == req
        except:
            raise RuntimeError("Communication trouble with Coldcard")

    def show_address(self, path, addr_fmt):
        # prompt user w/ addres, also returns it immediately.
        return self.dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    def get_version(self):
        # gives list of strings
        return self.dev.send_recv(CCProtocolPacker.version(), timeout=1000).split('\n')

    def sign_message_start(self, path, msg):
        # this starts the UX experience.
        self.dev.send_recv(CCProtocolPacker.sign_message(msg, path), timeout=None)

    def sign_message_poll(self):
        # poll device... if user has approved, will get tuple: (addr, sig) else None
        return self.dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)

    def sign_transaction_start(self, raw_psbt, finalize=True):
        # Multiple steps to sign:
        # - upload binary
        # - start signing UX
        # - wait for coldcard to complete process, or have it refused.
        # - download resulting txn
        assert 20 <= len(raw_psbt) < MAX_TXN_LEN, 'PSBT is too big'
        dlen, chk = self.dev.upload_file(raw_psbt)

        resp = self.dev.send_recv(CCProtocolPacker.sign_transaction(dlen, chk, finalize=finalize),
                                    timeout=None)

        if resp != None:
            raise ValueError(resp)

    def sign_transaction_poll(self):
        # poll device... if user has approved, will get tuple: (legnth, checksum) else None
        return self.dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)

    def download_file(self, length, checksum, file_number=1):
        # get a file
        return self.dev.download_file(length, checksum, file_number=file_number)

        

class Coldcard_KeyStore(Hardware_KeyStore):
    hw_type = 'coldcard'
    device = 'Coldcard'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.force_watching_only = False
        self.ux_busy = False

        # Seems like only the derivation path and resulting **derived** xpub is stored in
        # the wallet file... however, we need to know at least the fingerprint of the master
        # xpub to verify against MiTM, and also so we can put the right value into the subkey paths
        # of PSBT files that might be generated offline. 
        # - save the fingerprint of the master xpub, as "xfp"
        # - it's a LE32 int, but hex more natural way to see it
        # - device reports these value during encryption setup process
        lab = d['label']
        if hasattr(lab, 'xfp'):
            # initial setup
            self.ckcc_xfp = lab.xfp
            self.ckcc_xpub = lab.xpub
        else:
            # wallet load: fatal if missing, we need them!
            self.ckcc_xfp = d['ckcc_xfp']
            self.ckcc_xpub = d['ckcc_xpub']

    def dump(self):
        # our additions to the stored data about keystore -- only during creation?
        d = Hardware_KeyStore.dump(self)

        d['ckcc_xfp'] = self.ckcc_xfp
        d['ckcc_xpub'] = self.ckcc_xpub

        return d

    def get_derivation(self):
        return self.derivation

    def get_client(self):
        # called when user tries to do something like view address, sign somthing.
        # - not called during probing/setup
        rv = self.plugin.get_client(self)
        if rv:
            rv.verify_connection(self.ckcc_xfp, self.ckcc_xpub)

        return rv

    def give_error(self, message, clear_client=False):
        self.logger.info(message)
        if not self.ux_busy:
            self.handler.show_error(message)
        else:
            self.ux_busy = False
        if clear_client:
            self.client = None
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
    def sign_message(self, sequence, message, password):
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

        client = self.get_client()
        path = self.get_derivation() + ("/%d/%d" % sequence)
        try:
            cl = self.get_client()
            try:
                self.handler.show_message("Signing message (using %s)..." % path)

                cl.sign_message_start(path, msg)

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
            self.give_error(e, True)

        # give empty bytes for error cases; it seems to clear the old signature box
        return b''

    def build_psbt(self, tx: Transaction, wallet=None, xfp=None):
        # Render a PSBT file, for upload to Coldcard.
        # 
        if xfp is None:
            # need fingerprint of MASTER xpub, not the derived key
            xfp = self.ckcc_xfp

        inputs = tx.inputs()

        if 'prev_tx' not in inputs[0]:
            # fetch info about inputs, if needed?
            # - needed during export PSBT flow, not normal online signing
            assert wallet, 'need wallet reference'
            wallet.add_hw_info(tx)

        # wallet.add_hw_info installs this attr
        assert tx.output_info is not None, 'need data about outputs'

        # Build map of pubkey needed as derivation from master, in PSBT binary format
        # 1) binary version of the common subpath for all keys
        #       m/ => fingerprint LE32
        #       a/b/c => ints
        base_path = pack('<I', xfp)
        for x in self.get_derivation()[2:].split('/'):
            if x.endswith("'"):
                x = int(x[:-1]) | 0x80000000
            else:
                x = int(x)
            base_path += pack('<I', x)

        # 2) all used keys in transaction
        subkeys = {}
        derivations = self.get_tx_derivations(tx)
        for xpubkey in derivations:
            pubkey = xpubkey_to_pubkey(xpubkey)

            # assuming depth two, non-harded: change + index
            aa, bb = derivations[xpubkey]
            assert 0 <= aa < 0x80000000
            assert 0 <= bb < 0x80000000

            subkeys[bfh(pubkey)] = base_path + pack('<II', aa, bb)
            
        for txin in inputs:
            if txin['type'] == 'coinbase':
                self.give_error("Coinbase not supported")

            if txin['type'] in ['p2sh', 'p2wsh-p2sh', 'p2wsh']:
                self.give_error('No support yet for inputs of type: ' + txin['type'])

        # Construct PSBT from start to finish.
        out_fd = io.BytesIO()
        out_fd.write(b'psbt\xff')

        def write_kv(ktype, val, key=b''):
            # serialize helper: write w/ size and key byte
            out_fd.write(my_var_int(1 + len(key)))
            out_fd.write(bytes([ktype]) + key)

            if isinstance(val, str):
                val = bfh(val)

            out_fd.write(my_var_int(len(val)))
            out_fd.write(val)


        # global section: just the unsigned txn
        class CustomTXSerialization(Transaction):
            @classmethod
            def input_script(cls, txin, estimate_size=False):
                return ''

        unsigned = bfh(CustomTXSerialization(tx.serialize()).serialize_to_network(witness=False))
        write_kv(PSBT_GLOBAL_UNSIGNED_TX, unsigned)

        # end globals section
        out_fd.write(b'\x00')

        # inputs section
        for txin in inputs:
            if Transaction.is_segwit_input(txin):
                utxo = txin['prev_tx'].outputs()[txin['prevout_n']]
                spendable = txin['prev_tx'].serialize_output(utxo)
                write_kv(PSBT_IN_WITNESS_UTXO, spendable)
            else:
                write_kv(PSBT_IN_NON_WITNESS_UTXO, str(txin['prev_tx']))

            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)

            pubkeys = [bfh(k) for k in pubkeys]

            for k in pubkeys:
                write_kv(PSBT_IN_BIP32_DERIVATION, subkeys[k], k)

                if txin['type'] == 'p2wpkh-p2sh':
                    assert len(pubkeys) == 1, 'can be only one redeem script per input'
                    pa = hash_160(k)
                    assert len(pa) == 20
                    write_kv(PSBT_IN_REDEEM_SCRIPT, b'\x00\x14'+pa)

            out_fd.write(b'\x00')

        # outputs section
        for o in tx.outputs():
            # can be empty, but must be present, and helpful to show change inputs
            # wallet.add_hw_info() adds some data about change outputs into tx.output_info
            if o.address in tx.output_info:
                # this address "is_mine" but might not be change (I like to sent to myself)
                output_info = tx.output_info.get(o.address)
                index, xpubs = output_info.address_index, output_info.sorted_xpubs

                if index[0] == 1 and len(index) == 2:
                    # it is a change output (based on our standard derivation path)
                    assert len(xpubs) == 1      # not expecting multisig
                    xpubkey = xpubs[0]

                    # document its bip32 derivation in output section
                    aa, bb = index
                    assert 0 <= aa < 0x80000000
                    assert 0 <= bb < 0x80000000

                    deriv = base_path + pack('<II', aa, bb)
                    pubkey = bfh(self.get_pubkey_from_xpub(xpubkey, index))

                    write_kv(PSBT_OUT_BIP32_DERIVATION, deriv, pubkey)

                    if output_info.script_type == 'p2wpkh-p2sh':
                        pa = hash_160(pubkey)
                        assert len(pa) == 20
                        write_kv(PSBT_OUT_REDEEM_SCRIPT, b'\x00\x14' + pa)

            out_fd.write(b'\x00')

        return out_fd.getvalue()


    @wrap_busy
    def sign_transaction(self, tx, password):
        # Build a PSBT in memory, upload it for signing.
        # - we can also work offline (without paired device present)
        if tx.is_complete():
            return

        client = self.get_client()

        assert client.dev.master_fingerprint == self.ckcc_xfp

        raw_psbt = self.build_psbt(tx)

        #open('debug.psbt', 'wb').write(out_fd.getvalue())

        try:
            try:
                self.handler.show_message("Authorize Transaction...")

                client.sign_transaction_start(raw_psbt, True)

                while 1:
                    # How to kill some time, without locking UI?
                    time.sleep(0.250)

                    resp = client.sign_transaction_poll()
                    if resp is not None:
                        break

                rlen, rsha = resp
            
                # download the resulting txn.
                new_raw = client.download_file(rlen, rsha)

            finally:
                self.handler.finished()

        except (CCUserRefused, CCBusyError) as exc:
            self.logger.info(f'Did not sign: {exc}')
            self.handler.show_error(str(exc))
            return
        except BaseException as e:
            self.logger.exception('')
            self.give_error(e, True)
            return

        # trust the coldcard to re-searilize final product right?
        tx.update(bh2u(new_raw))

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
        address_path = self.get_derivation()[2:] + "/%d/%d"%sequence
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



class ColdcardPlugin(HW_PluginBase):
    keystore_class = Coldcard_KeyStore
    minimum_library = (0, 7, 2)
    client = None

    DEVICE_IDS = [
        (COINKITE_VID, CKCC_PID),
        (COINKITE_VID, CKCC_SIMULATED_PID)
    ]

    #SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
    SUPPORTED_XTYPES = ('standard', 'p2wpkh', 'p2wpkh-p2sh')

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return

        self.device_manager().register_devices(self.DEVICE_IDS)
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

    def create_client(self, device, handler):
        if handler:
            self.handler = handler

        # We are given a HID device, or at least some details about it.
        # Not sure why not we aren't just given a HID library handle, but
        # the 'path' is unabiguous, so we'll use that.
        try:
            rv = CKCCClient(self, handler, device.path,
                    is_simulator=(device.product_key[1] == CKCC_SIMULATED_PID))
            return rv
        except:
            self.logger.info('late failure connecting to device?')
            return None

    def setup_device(self, device_info, wizard, purpose):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise UserFacingException(_('Failed to create a client for this device.') + '\n' +
                                      _('Make sure it is in the correct state.'))
        client.handler = self.create_handler(wizard)

    def get_xpub(self, device_id, derivation, xtype, wizard):
        # this seems to be part of the pairing process only, not during normal ops?
        # base_wizard:on_hw_derivation
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script is not supported with {}.').format(self.device))
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        client.ping_check()

        xpub = client.get_xpub(derivation, xtype)
        return xpub

    def get_client(self, keystore, force_pair=True):
        # All client interaction should not be in the main GUI thread
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        # returns the client for a given keystore. can use xpub
        #if client:
        #    client.used()
        if client is not None:
            client.ping_check()
        return client

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return

        # Standard_Wallet => not multisig, must be bip32
        if type(wallet) is not Standard_Wallet:
            keystore.handler.show_error(_('This function is only available for standard wallets when using {}.').format(self.device))
            return

        sequence = wallet.get_address_index(address)
        txin_type = wallet.get_txin_type(address)
        keystore.show_address(sequence, txin_type)

# EOF
