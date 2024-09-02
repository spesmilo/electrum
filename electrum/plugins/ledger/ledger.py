# Some parts of this code are adapted from bitcoin-core/HWI:
# https://github.com/bitcoin-core/HWI/blob/e731395bde13362950e9f13e01689c475545e4dc/hwilib/devices/ledger.py

from abc import ABC, abstractmethod
import base64
import hashlib
from typing import Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING

from electrum import bip32, constants, ecc
from electrum import descriptor
from electrum.bip32 import BIP32Node, convert_bip32_intpath_to_strpath, normalize_bip32_derivation
from electrum.bitcoin import EncodeBase58Check, is_b58_address, is_segwit_script_type, var_int
from electrum.crypto import hash_160
from electrum.i18n import _
from electrum.keystore import Hardware_KeyStore
from electrum.logging import get_logger
from electrum.plugin import Device, runs_in_hwd_thread
from electrum.transaction import PartialTransaction, Transaction, PartialTxInput
from electrum.util import bfh, UserFacingException, versiontuple
from electrum.wallet import Standard_Wallet

from ..hw_wallet import HardwareClientBase, HW_PluginBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch, validate_op_return_output, LibraryFoundButUnusable

if TYPE_CHECKING:
    from electrum.plugin import DeviceInfo
    from electrum.wizard import NewWalletWizard

_logger = get_logger(__name__)


try:
    import ledger_bitcoin
    from ledger_bitcoin import WalletPolicy, MultisigWallet, AddressType, Chain
    from ledger_bitcoin.exception.errors import DenyError, NotSupportedError, SecurityStatusNotSatisfiedError
    from ledger_bitcoin.key import KeyOriginInfo
    from ledgercomm.interfaces.hid_device import HID

    # legacy imports
    # note: we could replace "btchip" with "ledger_bitcoin.btchip" but the latter does not support HW.1
    import hid
    from btchip.btchipComm import HIDDongleHIDAPI
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipException import BTChipException

    LEDGER_BITCOIN = True
except ImportError as e:
    if not (isinstance(e, ModuleNotFoundError) and e.name == 'ledger_bitcoin'):
        _logger.exception('error importing ledger plugin deps')

    LEDGER_BITCOIN = False


MSG_NEEDS_FW_UPDATE_GENERIC = _('Firmware version too old. Please update at') + \
    ' https://www.ledger.com'
MSG_NEEDS_FW_UPDATE_SEGWIT = _('Firmware version (or "Bitcoin" app) too old for Segwit support. Please update at') + \
    ' https://www.ledger.com'
MULTI_OUTPUT_SUPPORT = '1.1.4'
SEGWIT_SUPPORT = '1.1.10'
SEGWIT_SUPPORT_SPECIAL = '1.0.4'
SEGWIT_TRUSTEDINPUTS = '1.4.0'


def is_policy_standard(wp: 'WalletPolicy', fpr: bytes, exp_coin_type: int) -> bool:
    """Returns True if the wallet policy can be used without registration."""

    if wp.name != "" or wp.n_keys != 1:
        return False

    key_info = wp.keys_info[0]

    if key_info[0] != '[':
        # no key origin info
        return False

    try:
        key_orig_end = key_info.index(']')
    except ValueError:
        # invalid key_info
        return False

    key_fpr, key_path = key_info[1:key_orig_end].split('/', maxsplit=1)

    if key_fpr != fpr.hex():
        # not an internal key
        return False

    key_path_parts = key_path.split('/')

    # Account key should be exactly 3 hardened derivation steps
    if len(key_path_parts) != 3 or any(part[-1] != "'" for part in key_path_parts):
        return False

    purpose, coin_type, account_index = key_path_parts

    if coin_type != f"{exp_coin_type}'" or int(account_index[:-1]) > 100:
        return False

    if wp.descriptor_template == "pkh(@0/**)":
        # BIP-44
        return purpose == "44'"
    elif wp.descriptor_template == "sh(wpkh(@0/**))":
        # BIP-49, nested SegWit
        return purpose == "49'"
    elif wp.descriptor_template == "wpkh(@0/**)":
        # BIP-84, native SegWit
        return purpose == "84'"
    elif wp.descriptor_template == "tr(@0/**)":
        # BIP-86, taproot single key
        return purpose == "86'"
    else:
        # unknown
        return False


def convert_xpub(xpub: str, xtype='standard') -> str:
    bip32node = BIP32Node.from_xkey(xpub)
    return BIP32Node(
        xtype=xtype,
        eckey=bip32node.eckey,
        chaincode=bip32node.chaincode,
        depth=bip32node.depth,
        fingerprint=bip32node.fingerprint,
        child_number=bip32node.child_number).to_xpub()


def test_pin_unlocked(func):
    """Function decorator to test the Ledger for being unlocked, and if not,
    raise a human-readable exception.
    """
    def catch_exception(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except SecurityStatusNotSatisfiedError:
            raise UserFacingException(_('Your Ledger is locked. Please unlock it.'))
    return catch_exception


# from HWI
def is_witness(script: bytes) -> Tuple[bool, int, bytes]:
    """
    Determine whether a script is a segwit output script.
    If so, also returns the witness version and witness program.

    :param script: The script
    :returns: A tuple of a bool indicating whether the script is a segwit output script,
        an int representing the witness version,
        and the bytes of the witness program.
    """
    if len(script) < 4 or len(script) > 42:
        return (False, 0, b"")

    if script[0] != 0 and (script[0] < 81 or script[0] > 96):
        return (False, 0, b"")

    if script[1] + 2 == len(script):
        return (True, script[0] - 0x50 if script[0] else 0, script[2:])

    return (False, 0, b"")


# from HWI
# Only handles up to 15 of 15. Returns None if this script is not a
# multisig script. Returns (m, pubkeys) otherwise.
def parse_multisig(script: bytes) -> Optional[Tuple[int, Sequence[bytes]]]:
    """
    Determine whether a script is a multisig script. If so, determine the parameters of that multisig.

    :param script: The script
    :returns: ``None`` if the script is not multisig.
        If multisig, returns a tuple of the number of signers required,
        and a sequence of public key bytes.
    """
    # Get m
    m = script[0] - 80
    if m < 1 or m > 15:
        return None

    # Get pubkeys
    pubkeys = []
    offset = 1
    while True:
        pubkey_len = script[offset]
        if pubkey_len != 33:
            break
        offset += 1
        pubkeys.append(script[offset:offset + 33])
        offset += 33

    # Check things at the end
    n = script[offset] - 80
    if n != len(pubkeys):
        return None
    offset += 1
    op_cms = script[offset]
    if op_cms != 174:
        return None

    return (m, pubkeys)


HARDENED_FLAG = 1 << 31


def H_(x: int) -> int:
    """
    Shortcut function that "hardens" a number in a BIP44 path.
    """
    return x | HARDENED_FLAG


def is_hardened(i: int) -> bool:
    """
    Returns whether an index is hardened
    """
    return i & HARDENED_FLAG != 0


def get_bip44_purpose(addrtype: 'AddressType') -> int:
    """
    Determine the BIP 44 purpose based on the given :class:`~hwilib.common.AddressType`.

    :param addrtype: The address type
    """
    if addrtype == AddressType.LEGACY:
        return 44
    elif addrtype == AddressType.SH_WIT:
        return 49
    elif addrtype == AddressType.WIT:
        return 84
    elif addrtype == AddressType.TAP:
        return 86
    else:
        raise ValueError("Unknown address type")


def get_bip44_chain(chain: 'Chain') -> int:
    """
    Determine the BIP 44 coin type based on the Bitcoin chain type.

    For the Bitcoin mainnet chain, this returns 0. For the other chains, this returns 1.

    :param chain: The chain
    """
    if chain == Chain.MAIN:
        return 0
    else:
        return 1


def get_addrtype_from_bip44_purpose(index: int) -> Optional['AddressType']:
    purpose = index & ~HARDENED_FLAG

    if purpose == 44:
        return AddressType.LEGACY
    elif purpose == 49:
        return AddressType.SH_WIT
    elif purpose == 84:
        return AddressType.WIT
    elif purpose == 86:
        return AddressType.TAP
    else:
        return None


def is_standard_path(
    path: Sequence[int],
    addrtype: 'AddressType',
    chain: 'Chain',
) -> bool:
    if len(path) != 5:
        return False
    if not is_hardened(path[0]) or not is_hardened(path[1]) or not is_hardened(path[2]):
        return False
    if is_hardened(path[3]) or is_hardened(path[4]):
        return False
    computed_addrtype = get_addrtype_from_bip44_purpose(path[0])
    if computed_addrtype is None:
        return False
    if computed_addrtype != addrtype:
        return False
    if path[1] != H_(get_bip44_chain(chain)):
        return False
    if path[3] not in [0, 1]:
        return False
    return True


def get_chain() -> 'Chain':
    if constants.net.NET_NAME == "mainnet":
        return Chain.MAIN
    elif constants.net.NET_NAME == "testnet":
        return Chain.TEST
    elif constants.net.NET_NAME == "signet":
        return Chain.SIGNET
    elif constants.net.NET_NAME == "regtest":
        return Chain.REGTEST
    else:
        raise ValueError("Unsupported network")


class Ledger_Client(HardwareClientBase, ABC):
    is_legacy: bool

    @staticmethod
    def construct_new(*args, device: Device, **kwargs) -> 'Ledger_Client':
        """The 'real' constructor, that automatically decides which subclass to use."""
        if LedgerPlugin.is_hw1(device.product_key):
            return Ledger_Client_Legacy_HW1(*args, **kwargs, device=device)
        # for nano S or newer hw, decide which client impl to use based on software/firmware version:
        hid_device = HID()
        hid_device.path = device.path
        hid_device.open()
        transport = ledger_bitcoin.TransportClient('hid', hid=hid_device)
        try:
            cl = ledger_bitcoin.createClient(transport, chain=get_chain())
        except (ledger_bitcoin.exception.errors.InsNotSupportedError,
                ledger_bitcoin.exception.errors.ClaNotSupportedError) as e:
            # This can happen on very old versions.
            # E.g. with a "nano s", with bitcoin app 1.1.10, SE 1.3.1, MCU 1.0,
            #      - on machine one, ghost43 got InsNotSupportedError
            #      - on machine two, thomasv got ClaNotSupportedError
            #      unclear why the different exceptions, ledger_bitcoin version 0.2.1 in both cases
            _logger.info(f"ledger_bitcoin.createClient() got exc: {e}. falling back to old plugin.")
            cl = None
        if isinstance(cl, ledger_bitcoin.client.NewClient):
            return Ledger_Client_New(hid_device, *args, **kwargs)
        else:
            return Ledger_Client_Legacy(hid_device, *args, **kwargs)

    def __init__(self, *, plugin: HW_PluginBase):
        HardwareClientBase.__init__(self, plugin=plugin)

    def get_master_fingerprint(self) -> bytes:
        return self.request_root_fingerprint_from_device()

    @abstractmethod
    def show_address(self, address_path: str, txin_type: str):
        pass

    @abstractmethod
    def sign_transaction(self, keystore: Hardware_KeyStore, tx: PartialTransaction, password: str):
        pass

    @abstractmethod
    def sign_message(
            self,
            address_path: str,
            message: str,
            password,
            *,
            script_type: Optional[str] = None,
    ) -> bytes:
        pass


class Ledger_Client_Legacy(Ledger_Client):
    """Client based on the bitchip library, targeting versions 2.0.* and below."""
    is_legacy = True

    def __init__(self, hidDevice: 'HID', *, product_key: Tuple[int, int],
                 plugin: HW_PluginBase):
        Ledger_Client.__init__(self, plugin=plugin)

        # Hack, we close the old object and instantiate a new one
        hidDevice.close()
        dev = hid.device()
        dev.open_path(hidDevice.path)
        dev.set_nonblocking(True)
        self.dongleObject = btchip(HIDDongleHIDAPI(dev, True, False))

        self.signing = False

        self._product_key = product_key
        self._soft_device_id = None

    def is_pairable(self):
        return True

    def set_and_unset_signing(func):
        """Function decorator to set and unset self.signing."""
        def wrapper(self, *args, **kwargs):
            try:
                self.signing = True
                return func(self, *args, **kwargs)
            finally:
                self.signing = False
        return wrapper

    def give_error(self, message):
        _logger.info(message)
        if not self.signing:
            self.handler.show_error(message)
        else:
            self.signing = False
        raise UserFacingException(message)

    @runs_in_hwd_thread
    def close(self):
        self.dongleObject.dongle.close()

    def is_initialized(self):
        return True

    @runs_in_hwd_thread
    def get_soft_device_id(self):
        if self._soft_device_id is None:
            # modern ledger can provide xpub without user interaction
            # (hw1 would prompt for PIN)
            if not self.is_hw1():
                self._soft_device_id = self.request_root_fingerprint_from_device()
        return self._soft_device_id

    def is_hw1(self) -> bool:
        return LedgerPlugin.is_hw1(self._product_key)

    def device_model_name(self):
        return LedgerPlugin.device_name_from_product_key(self._product_key)

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        try:
            self.dongleObject.getFirmwareVersion()
        except BaseException:
            return False
        return True

    @runs_in_hwd_thread
    @test_pin_unlocked
    def get_xpub(self, bip32_path, xtype):
        self.checkDevice()
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        # self.get_client() # prompt for the PIN before displaying the dialog if necessary
        # self.handler.show_message("Computing master public key")
        if xtype in ['p2wpkh', 'p2wsh'] and not self.supports_native_segwit():
            raise UserFacingException(MSG_NEEDS_FW_UPDATE_SEGWIT)
        if xtype in ['p2wpkh-p2sh', 'p2wsh-p2sh'] and not self.supports_segwit():
            raise UserFacingException(MSG_NEEDS_FW_UPDATE_SEGWIT)
        bip32_path = bip32.normalize_bip32_derivation(bip32_path, hardened_char="'")
        bip32_intpath = bip32.convert_bip32_strpath_to_intpath(bip32_path)
        bip32_path = bip32_path[2:]  # cut off "m/"
        if len(bip32_intpath) >= 1:
            prevPath = bip32.convert_bip32_intpath_to_strpath(bip32_intpath[:-1])[2:]
            nodeData = self.dongleObject.getWalletPublicKey(prevPath)
            publicKey = compress_public_key(nodeData['publicKey'])
            fingerprint_bytes = hash_160(publicKey)[0:4]
            childnum_bytes = bip32_intpath[-1].to_bytes(length=4, byteorder="big")
        else:
            fingerprint_bytes = bytes(4)
            childnum_bytes = bytes(4)
        nodeData = self.dongleObject.getWalletPublicKey(bip32_path)
        publicKey = compress_public_key(nodeData['publicKey'])
        depth = len(bip32_intpath)
        return BIP32Node(xtype=xtype,
                         eckey=ecc.ECPubkey(bytes(publicKey)),
                         chaincode=nodeData['chainCode'],
                         depth=depth,
                         fingerprint=fingerprint_bytes,
                         child_number=childnum_bytes).to_xpub()

    def has_detached_pin_support(self, client: 'btchip'):
        try:
            client.getVerifyPinRemainingAttempts()
            return True
        except BTChipException as e:
            if e.sw == 0x6d00:
                return False
            raise e

    def is_pin_validated(self, client: 'btchip'):
        try:
            # Invalid SET OPERATION MODE to verify the PIN status
            client.dongle.exchange(bytearray([0xe0, 0x26, 0x00, 0x00, 0x01, 0xAB]))
        except BTChipException as e:
            if (e.sw == 0x6982):
                return False
            if (e.sw == 0x6A80):
                return True
            raise e

    def supports_multi_output(self):
        return self.multiOutputSupported

    def supports_segwit(self):
        return self.segwitSupported

    def supports_native_segwit(self):
        return self.nativeSegwitSupported

    def supports_segwit_trustedInputs(self):
        return self.segwitTrustedInputs

    @runs_in_hwd_thread
    def checkDevice(self):
        firmwareInfo = self.dongleObject.getFirmwareVersion()
        firmware = firmwareInfo['version']
        self.multiOutputSupported = versiontuple(firmware) >= versiontuple(MULTI_OUTPUT_SUPPORT)
        self.nativeSegwitSupported = versiontuple(firmware) >= versiontuple(SEGWIT_SUPPORT)
        self.segwitSupported = self.nativeSegwitSupported or (firmwareInfo['specialVersion'] == 0x20 and versiontuple(firmware) >= versiontuple(SEGWIT_SUPPORT_SPECIAL))
        self.segwitTrustedInputs = versiontuple(firmware) >= versiontuple(SEGWIT_TRUSTEDINPUTS)

    def password_dialog(self, msg=None):
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response

    @runs_in_hwd_thread
    @test_pin_unlocked
    @set_and_unset_signing
    def show_address(self, address_path: str, txin_type: str):
        self.handler.show_message(_("Showing address ..."))
        segwit = is_segwit_script_type(txin_type)
        segwitNative = txin_type == 'p2wpkh'
        try:
            self.dongleObject.getWalletPublicKey(address_path, showOnScreen=True, segwit=segwit, segwitNative=segwitNative)
        except BTChipException as e:
            if e.sw == 0x6985:  # cancelled by user
                pass
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            elif e.sw == 0x6b00:  # hw.1 raises this
                self.handler.show_error('{}\n{}\n{}'.format(
                    _('Error showing address') + ':',
                    e,
                    _('Your device might not have support for this functionality.')))
            else:
                _logger.exception('')
                self.handler.show_error(e)
        except BaseException as e:
            _logger.exception('')
            self.handler.show_error(e)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    @test_pin_unlocked
    @set_and_unset_signing
    def sign_transaction(self, keystore: Hardware_KeyStore, tx: PartialTransaction, password: str):
        if tx.is_complete():
            return

        inputs = []
        inputsPaths = []
        chipInputs = []
        redeemScripts = []
        changePath = ""
        output = None
        p2shTransaction = False
        segwitTransaction = False
        pin = ""
        # prompt for the PIN before displaying the dialog if necessary

        def is_txin_legacy_multisig(txin: PartialTxInput) -> bool:
            desc = txin.script_descriptor
            return (isinstance(desc, descriptor.SHDescriptor)
                    and isinstance(desc.subdescriptors[0], descriptor.MultisigDescriptor))

        # Fetch inputs of the transaction to sign
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                self.give_error("Coinbase not supported")     # should never happen

            if is_txin_legacy_multisig(txin):
                p2shTransaction = True

            if txin.is_p2sh_segwit():
                if not self.supports_segwit():
                    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
                segwitTransaction = True

            if txin.is_native_segwit():
                if not self.supports_native_segwit():
                    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
                segwitTransaction = True

            my_pubkey, full_path = keystore.find_my_pubkey_in_txinout(txin)
            if not full_path:
                self.give_error("No matching pubkey for sign_transaction")  # should never happen
            full_path = convert_bip32_intpath_to_strpath(full_path)[2:]

            redeemScript = Transaction.get_preimage_script(txin).hex()
            txin_prev_tx = txin.utxo
            if txin_prev_tx is None and not txin.is_segwit():
                raise UserFacingException(_('Missing previous tx for legacy input.'))
            txin_prev_tx_raw = txin_prev_tx.serialize() if txin_prev_tx else None
            inputs.append([txin_prev_tx_raw,
                           txin.prevout.out_idx,
                           redeemScript,
                           txin.prevout.txid.hex(),
                           my_pubkey,
                           txin.nsequence,
                           txin.value_sats()])
            inputsPaths.append(full_path)

        # Sanity check
        if p2shTransaction:
            for txin in tx.inputs():
                if not is_txin_legacy_multisig(txin):
                    self.give_error("P2SH / regular input mixed in same transaction not supported")  # should never happen

        txOutput = bytearray()
        txOutput += var_int(len(tx.outputs()))
        for o in tx.outputs():
            txOutput += int.to_bytes(o.value, length=8, byteorder="little", signed=False)
            script = o.scriptpubkey
            txOutput += var_int(len(script))
            txOutput += script
        txOutput = bytes(txOutput)

        if not self.supports_multi_output():
            if len(tx.outputs()) > 2:
                self.give_error("Transaction with more than 2 outputs not supported")
        for txout in tx.outputs():
            if self.is_hw1() and txout.address and not is_b58_address(txout.address):
                self.give_error(_("This {} device can only send to base58 addresses.").format(keystore.device))
            if not txout.address:
                if self.is_hw1():
                    self.give_error(_("Only address outputs are supported by {}").format(keystore.device))
                # note: max_size based on https://github.com/LedgerHQ/ledger-app-btc/commit/3a78dee9c0484821df58975803e40d58fbfc2c38#diff-c61ccd96a6d8b54d48f54a3bc4dfa7e2R26
                validate_op_return_output(txout, max_size=190)

        # Output "change" detection
        # - only one output and one change is authorized (for hw.1 and nano)
        # - at most one output can bypass confirmation (~change) (for all)
        if not p2shTransaction:
            has_change = False
            any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)
            for txout in tx.outputs():
                if txout.is_mine and len(tx.outputs()) > 1 \
                        and not has_change:
                    # prioritise hiding outputs on the 'change' branch from user
                    # because no more than one change address allowed
                    if txout.is_change == any_output_on_change_branch:
                        my_pubkey, changePath = keystore.find_my_pubkey_in_txinout(txout)
                        assert changePath
                        changePath = convert_bip32_intpath_to_strpath(changePath)[2:]
                        has_change = True
                    else:
                        output = txout.address
                else:
                    output = txout.address

        try:
            # Get trusted inputs from the original transactions
            for input_idx, utxo in enumerate(inputs):
                self.handler.show_message(_("Preparing transaction inputs...") + f" (phase1, {input_idx}/{len(inputs)})")
                sequence = int.to_bytes(utxo[5], length=4, byteorder="little", signed=False)
                if segwitTransaction and not self.supports_segwit_trustedInputs():
                    tmp = bfh(utxo[3])[::-1]
                    tmp += int.to_bytes(utxo[1], length=4, byteorder="little", signed=False)
                    tmp += int.to_bytes(utxo[6], length=8, byteorder="little", signed=False)  # txin['value']
                    chipInputs.append({'value': tmp, 'witness': True, 'sequence': sequence})
                    redeemScripts.append(bfh(utxo[2]))
                elif (not p2shTransaction) or self.supports_multi_output():
                    txtmp = bitcoinTransaction(bfh(utxo[0]))
                    trustedInput = self.dongleObject.getTrustedInput(txtmp, utxo[1])
                    trustedInput['sequence'] = sequence
                    if segwitTransaction:
                        trustedInput['witness'] = True
                    chipInputs.append(trustedInput)
                    if p2shTransaction or segwitTransaction:
                        redeemScripts.append(bfh(utxo[2]))
                    else:
                        redeemScripts.append(txtmp.outputs[utxo[1]].script)
                else:
                    tmp = bfh(utxo[3])[::-1]
                    tmp += int.to_bytes(utxo[1], length=4, byteorder="little", signed=False)
                    chipInputs.append({'value': tmp, 'sequence': sequence})
                    redeemScripts.append(bfh(utxo[2]))

            self.handler.show_message(_("Confirm Transaction on your Ledger device..."))
            # Sign all inputs
            firstTransaction = True
            inputIndex = 0
            rawTx = tx.serialize_to_network(include_sigs=False)
            if self.is_hw1():
                self.dongleObject.enableAlternate2fa(False)
            if segwitTransaction:
                self.dongleObject.startUntrustedTransaction(True, inputIndex, chipInputs, redeemScripts[inputIndex], version=tx.version)
                # we don't set meaningful outputAddress, amount and fees
                # as we only care about the alternateEncoding==True branch
                outputData = self.dongleObject.finalizeInput(b'', 0, 0, changePath, bfh(rawTx))
                outputData['outputData'] = txOutput
                if outputData['confirmationNeeded']:
                    outputData['address'] = output
                    self.handler.finished()
                    # do the authenticate dialog and get pin:
                    pin = self.handler.get_auth(outputData, client=self)
                    if not pin:
                        raise UserWarning()
                    self.handler.show_message(_("Confirmed. Signing Transaction..."))
                while inputIndex < len(inputs):
                    self.handler.show_message(_("Signing transaction...") + f" (phase2, {inputIndex}/{len(inputs)})")
                    singleInput = [chipInputs[inputIndex]]
                    self.dongleObject.startUntrustedTransaction(False, 0,
                                                                singleInput, redeemScripts[inputIndex], version=tx.version)
                    inputSignature = self.dongleObject.untrustedHashSign(inputsPaths[inputIndex], pin, lockTime=tx.locktime)
                    inputSignature[0] = 0x30  # force for 1.4.9+
                    my_pubkey = inputs[inputIndex][4]
                    tx.add_signature_to_txin(txin_idx=inputIndex,
                                             signing_pubkey=my_pubkey,
                                             sig=inputSignature)
                    inputIndex = inputIndex + 1
            else:
                while inputIndex < len(inputs):
                    self.handler.show_message(_("Signing transaction...") + f" (phase2, {inputIndex}/{len(inputs)})")
                    self.dongleObject.startUntrustedTransaction(firstTransaction, inputIndex, chipInputs, redeemScripts[inputIndex], version=tx.version)
                    # we don't set meaningful outputAddress, amount and fees
                    # as we only care about the alternateEncoding==True branch
                    outputData = self.dongleObject.finalizeInput(b'', 0, 0, changePath, bfh(rawTx))
                    outputData['outputData'] = txOutput
                    if outputData['confirmationNeeded']:
                        outputData['address'] = output
                        self.handler.finished()
                        # do the authenticate dialog and get pin:
                        pin = self.handler.get_auth(outputData, client=self)
                        if not pin:
                            raise UserWarning()
                        self.handler.show_message(_("Confirmed. Signing Transaction..."))
                    else:
                        # Sign input with the provided PIN
                        inputSignature = self.dongleObject.untrustedHashSign(inputsPaths[inputIndex], pin, lockTime=tx.locktime)
                        inputSignature[0] = 0x30  # force for 1.4.9+
                        my_pubkey = inputs[inputIndex][4]
                        tx.add_signature_to_txin(txin_idx=inputIndex,
                                                 signing_pubkey=my_pubkey,
                                                 sig=inputSignature)
                        inputIndex = inputIndex + 1
                    firstTransaction = False
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return
        except BTChipException as e:
            if e.sw in (0x6985, 0x6d00):  # cancelled by user
                return
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            else:
                _logger.exception('')
                self.give_error(e)
        except BaseException as e:
            _logger.exception('')
            self.give_error(e)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    @test_pin_unlocked
    @set_and_unset_signing
    def sign_message(
            self,
            address_path: str,
            message: str,
            password,
            *,
            script_type: Optional[str] = None,
    ) -> bytes:
        message = message.encode('utf8')
        message_hash = hashlib.sha256(message).hexdigest().upper()

        self.handler.show_message("Signing message ...\r\nMessage hash: " + message_hash)
        try:
            info = self.dongleObject.signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                # do the authenticate dialog and get pin:
                pin = self.handler.get_auth(info, client=self)
                if not pin:
                    raise UserWarning(_('Cancelled by user'))
                pin = str(pin).encode()
            signature = self.dongleObject.signMessageSign(pin)
        except BTChipException as e:
            if e.sw == 0x6a80:
                self.give_error("Unfortunately, this message cannot be signed by the Ledger wallet. "
                                "Only alphanumerical messages shorter than 140 characters are supported. "
                                "Please remove any extra characters (tab, carriage return) and retry.")
            elif e.sw == 0x6985:  # cancelled by user
                return b''
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            else:
                self.give_error(e)
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return b''
        except Exception as e:
            self.give_error(e)
        finally:
            self.handler.finished()
        # Parse the ASN.1 signature
        rLength = signature[3]
        r = signature[4: 4 + rLength]
        sLength = signature[4 + rLength + 1]
        s = signature[4 + rLength + 2:]
        if rLength == 33:
            r = r[1:]
        if sLength == 33:
            s = s[1:]
        # And convert it

        # Pad r and s points with 0x00 bytes when the point is small to get valid signature.
        r_padded = bytes([0x00]) * (32 - len(r)) + r
        s_padded = bytes([0x00]) * (32 - len(s)) + s

        return bytes([27 + 4 + (signature[0] & 0x01)]) + r_padded + s_padded


class Ledger_Client_Legacy_HW1(Ledger_Client_Legacy):
    """Even "legacy-er" client for deprecated HW.1 support."""

    MIN_SUPPORTED_HW1_FW_VERSION = "1.0.2"

    def __init__(self, product_key: Tuple[int, int],
                 plugin: HW_PluginBase, device: 'Device'):
        # note: Ledger_Client_Legacy.__init__ is *not* called
        Ledger_Client.__init__(self, plugin=plugin)
        self._product_key = product_key
        assert self.is_hw1()

        ledger = device.product_key[1] in (0x3b7c, 0x4b7c)
        dev = hid.device()
        dev.open_path(device.path)
        dev.set_nonblocking(True)
        hid_device = HIDDongleHIDAPI(dev, ledger, debug=False)
        self.dongleObject = btchip(hid_device)

        self._preflightDone = False
        self.signing = False
        self._soft_device_id = None

    @runs_in_hwd_thread
    def checkDevice(self):
        super().checkDevice()
        self._perform_hw1_preflight()

    def _perform_hw1_preflight(self):
        assert self.is_hw1()
        if self._preflightDone:
            return
        try:
            firmwareInfo = self.dongleObject.getFirmwareVersion()
            firmware = firmwareInfo['version']
            if versiontuple(firmware) < versiontuple(self.MIN_SUPPORTED_HW1_FW_VERSION):
                self.close()
                raise UserFacingException(
                    _("Unsupported device firmware (too old).") + f"\nInstalled: {firmware}. Needed: >={self.MIN_SUPPORTED_HW1_FW_VERSION}")
            try:
                self.dongleObject.getOperationMode()
            except BTChipException as e:
                if (e.sw == 0x6985):
                    self.close()
                    self.handler.get_setup()
                    # Acquire the new client on the next run
                else:
                    raise e
            if self.has_detached_pin_support(self.dongleObject) and not self.is_pin_validated(self.dongleObject):
                assert self.handler, "no handler for client"
                remaining_attempts = self.dongleObject.getVerifyPinRemainingAttempts()
                if remaining_attempts != 1:
                    msg = "Enter your Ledger PIN - remaining attempts : " + str(remaining_attempts)
                else:
                    msg = "Enter your Ledger PIN - WARNING : LAST ATTEMPT. If the PIN is not correct, the dongle will be wiped."
                confirmed, p, pin = self.password_dialog(msg)
                if not confirmed:
                    raise UserFacingException(_('Aborted by user - please unplug the dongle and plug it again before retrying'))
                pin = pin.encode()
                self.dongleObject.verifyPin(pin)
        except BTChipException as e:
            if (e.sw == 0x6faa):
                raise UserFacingException(_('Dongle is temporarily locked - please unplug it and replug it again'))
            if ((e.sw & 0xFFF0) == 0x63c0):
                raise UserFacingException(_('Invalid PIN - please unplug the dongle and plug it again before retrying'))
            if e.sw == 0x6f00 and e.message == 'Invalid channel':
                # based on docs 0x6f00 might be a more general error, hence we also compare message to be sure
                raise UserFacingException(_("Invalid channel.\nPlease make sure that 'Browser support' is disabled on your device."))
            if e.sw == 0x6d00 or e.sw == 0x6700:
                raise UserFacingException(_("Device not in Bitcoin mode")) from e
            raise e
        else:
            deprecation_warning = (
                "This Ledger device (HW.1) is being deprecated.\n\nIt is no longer supported by Ledger.\n"
                "Future versions of Electrum will no longer be compatible with it.\n\n"
                "You should move your coins and migrate to a modern hardware device.")
            _logger.warning(deprecation_warning.replace("\n", " "))
            if self.handler:
                self.handler.show_message(deprecation_warning)
            self._preflightDone = True


class Ledger_Client_New(Ledger_Client):
    """Client based on the ledger_bitcoin library, targeting versions 2.1.* and above."""

    is_legacy = False

    def __init__(self, hidDevice: 'HID', *, product_key: Tuple[int, int],
                 plugin: HW_PluginBase):
        Ledger_Client.__init__(self, plugin=plugin)

        transport = ledger_bitcoin.TransportClient('hid', hid=hidDevice)
        self.client = ledger_bitcoin.client.NewClient(transport, get_chain())

        self._product_key = product_key
        self._soft_device_id = None

        self.master_fingerprint = None

        self._known_xpubs: Dict[str, str] = {}  # path ==> xpub
        self._registered_policies: Dict[bytes, bytes] = {}  # wallet id => wallet hmac

    def is_pairable(self):
        return True

    @runs_in_hwd_thread
    def close(self):
        self.client.stop()

    def is_initialized(self):
        return True

    @runs_in_hwd_thread
    def get_soft_device_id(self):
        if self._soft_device_id is None:
            self._soft_device_id = self.request_root_fingerprint_from_device()
        return self._soft_device_id

    def device_model_name(self):
        return LedgerPlugin.device_name_from_product_key(self._product_key)

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        try:
            self.client.get_version()
        except BaseException:
            return False
        return True

    @runs_in_hwd_thread
    @test_pin_unlocked
    def get_xpub(self, bip32_path: str, xtype):
        # try silently first; if not a standard path, repeat with on-screen display

        bip32_path = normalize_bip32_derivation(bip32_path, hardened_char="'")

        # cache known path/xpubs combinations in order to avoid requesting them many times
        if bip32_path in self._known_xpubs:
            xpub = self._known_xpubs[bip32_path]
        else:
            try:
                xpub = self.client.get_extended_pubkey(bip32_path)
            except NotSupportedError:
                xpub = self.client.get_extended_pubkey(bip32_path, True)
            self._known_xpubs[bip32_path] = xpub

        # Ledger always returns 'standard' xpubs; convert to the right xtype
        return convert_xpub(xpub, xtype)

    @runs_in_hwd_thread
    def request_root_fingerprint_from_device(self) -> str:
        return self.client.get_master_fingerprint().hex()

    @runs_in_hwd_thread
    @test_pin_unlocked
    def get_master_fingerprint(self) -> bytes:
        if self.master_fingerprint is None:
            self.master_fingerprint = self.client.get_master_fingerprint()
        return self.master_fingerprint

    @runs_in_hwd_thread
    @test_pin_unlocked
    def get_singlesig_default_wallet_policy(self, addr_type: 'AddressType', account: int) -> 'WalletPolicy':
        assert account >= HARDENED_FLAG

        if addr_type == AddressType.LEGACY:
            template = "pkh(@0/**)"
        elif addr_type == AddressType.WIT:
            template = "wpkh(@0/**)"
        elif addr_type == AddressType.SH_WIT:
            template = "sh(wpkh(@0/**))"
        elif addr_type == AddressType.TAP:
            template = "tr(@0/**)"
        else:
            raise ValueError("Unknown address type")

        fpr = self.get_master_fingerprint()
        key_origin_steps = f"{get_bip44_purpose(addr_type)}'/{get_bip44_chain(self.client.chain)}'/{account & ~HARDENED_FLAG}'"
        xpub = self.get_xpub(f"m/{key_origin_steps}", 'standard')
        key_str = f"[{fpr.hex()}/{key_origin_steps}]{xpub}"

        # Make the Wallet object
        return WalletPolicy(name="", descriptor_template=template, keys_info=[key_str])

    @runs_in_hwd_thread
    @test_pin_unlocked
    def get_singlesig_policy_for_path(self, path: str, xtype: str, master_fp: bytes) -> Optional['WalletPolicy']:
        path = path.replace("h", "'")
        path_parts = path.split("/")

        if not 5 <= len(path_parts) <= 6:
            raise UserFacingException(_('Unsupported derivation path: {}').format(path))

        path_root = "/".join(path_parts[:-2])

        fpr = self.get_master_fingerprint()

        # Ledger always uses standard xpubs in wallet policies
        xpub = self.get_xpub(f"m/{path_root}", 'standard')

        key_info = f"[{fpr.hex()}/{path_root}]{xpub}"

        if xtype == 'p2pkh':
            name = "Legacy P2PKH"
            descriptor_template = "pkh(@0/**)"
        elif xtype == 'p2wpkh-p2sh':
            name = "Nested SegWit"
            descriptor_template = "sh(wpkh(@0/**))"
        elif xtype == 'p2wpkh':
            name = "SegWit"
            descriptor_template = "wpkh(@0/**)"
        elif xtype == 'p2tr':
            name = "Taproot"
            descriptor_template = "tr(@0/**)"
        else:
            return None

        policy = WalletPolicy("", descriptor_template, [key_info])
        if is_policy_standard(policy, master_fp, constants.net.BIP44_COIN_TYPE):
            return policy

        # Non standard policy, so give it a name
        return WalletPolicy(name, descriptor_template, [key_info])

    def password_dialog(self, msg=None):
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response

    def _register_policy_if_needed(self, wallet_policy: 'WalletPolicy') -> Tuple[bytes, bytes]:
        # If the policy is not register, registers it and saves its hmac on success
        # Returns the pair of wallet id and wallet hmac
        if wallet_policy.id not in self._registered_policies:
            wallet_id, wallet_hmac = self.client.register_wallet(wallet_policy)
            assert wallet_id == wallet_policy.id
            self._registered_policies[wallet_id] = wallet_hmac
        return wallet_policy.id, self._registered_policies[wallet_policy.id]

    @runs_in_hwd_thread
    @test_pin_unlocked
    def show_address(self, address_path: str, txin_type: str):
        client_ledger = self.client
        self.handler.show_message(_("Showing address ..."))

        # TODO: generalize for multisignature

        try:
            master_fp = client_ledger.get_master_fingerprint()
            wallet_policy = self.get_singlesig_policy_for_path(address_path, txin_type, master_fp)

            change, addr_index = [int(i) for i in address_path.split("/")[-2:]]

            wallet_hmac = None
            if not is_policy_standard(wallet_policy, master_fp, constants.net.BIP44_COIN_TYPE):
                wallet_id, wallet_hmac = self._register_policy_if_needed(wallet_policy)

            self.client.get_wallet_address(wallet_policy, wallet_hmac, change, addr_index, True)
        except DenyError:
            pass  # cancelled by user
        except BaseException as e:
            _logger.exception('Error while showing an address')
            self.handler.show_error(e)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    @test_pin_unlocked
    def sign_transaction(self, keystore: Hardware_KeyStore, tx: PartialTransaction, password: str):
        if tx.is_complete():
            return

        # mostly adapted from HWI

        psbt_bytes = tx.serialize_as_bytes()
        psbt = ledger_bitcoin.client.PSBT()
        psbt.deserialize(base64.b64encode(psbt_bytes).decode('ascii'))

        try:

            master_fp = self.client.get_master_fingerprint()

            # Figure out which wallets are signing
            wallets: Dict[bytes, Tuple[AddressType, WalletPolicy, Optional[bytes]]] = {}
            for input_num, (electrum_txin, psbt_in) in enumerate(zip(tx.inputs(), psbt.inputs)):
                if electrum_txin.is_coinbase_input():
                    raise UserFacingException(_('Coinbase not supported'))     # should never happen

                utxo = None
                if psbt_in.witness_utxo:
                    utxo = psbt_in.witness_utxo
                if psbt_in.non_witness_utxo:
                    if psbt_in.prev_txid != psbt_in.non_witness_utxo.hash:
                        raise UserFacingException(_('Input {} has a non_witness_utxo with the wrong hash').format(input_num))
                    assert psbt_in.prev_out is not None
                    utxo = psbt_in.non_witness_utxo.vout[psbt_in.prev_out]

                if utxo is None:
                    continue
                if (desc := electrum_txin.script_descriptor) is None:
                    raise Exception("script_descriptor missing for txin ")
                scriptcode = desc.expand().scriptcode_for_sighash

                is_wit, wit_ver, __ = is_witness(psbt_in.redeem_script or utxo.scriptPubKey)

                script_addrtype = AddressType.LEGACY
                if is_wit:
                    # if it's a segwit spend (any version), make sure the witness_utxo is also present
                    psbt_in.witness_utxo = utxo

                    if electrum_txin.is_p2sh_segwit():
                        if wit_ver == 0:
                            script_addrtype = AddressType.SH_WIT
                        else:
                            raise UserFacingException(_('Cannot have witness v1+ in p2sh'))
                    else:
                        if wit_ver == 0:
                            script_addrtype = AddressType.WIT
                        elif wit_ver == 1:
                            script_addrtype = AddressType.TAP
                        else:
                            continue

                multisig = parse_multisig(scriptcode)
                if multisig is not None:
                    k, ms_pubkeys = multisig

                    # Figure out the parent xpubs
                    key_exprs: List[str] = []
                    ok = True
                    our_keys = 0
                    for pub in ms_pubkeys:
                        if pub in psbt_in.hd_keypaths:
                            pk_origin = psbt_in.hd_keypaths[pub]
                            if pk_origin.fingerprint == master_fp:
                                our_keys += 1

                            for xpub_bytes, xpub_origin in psbt.xpub.items():
                                xpub_str = EncodeBase58Check(xpub_bytes)
                                if (xpub_origin.fingerprint == pk_origin.fingerprint) and (xpub_origin.path == pk_origin.path[:len(xpub_origin.path)]):
                                    key_origin_full = pk_origin.to_string().replace('h', '\'')
                                    # strip last two steps of derivation
                                    key_origin_parts = key_origin_full.split('/')
                                    if len(key_origin_parts) < 3:
                                        raise UserFacingException(_('Unable to sign this transaction'))
                                    key_origin = '/'.join(key_origin_parts[:-2])

                                    key_exprs.append(f"[{key_origin}]{xpub_str}")
                                    break

                            else:
                                # No xpub, Ledger will not accept this multisig
                                ok = False

                    if not ok:
                        continue

                    # Electrum uses sortedmulti; we make sure that the array of key information is normalized in a consistent order
                    key_exprs = list(sorted(key_exprs))

                    # Make and register the MultisigWallet
                    msw = MultisigWallet(f"{k} of {len(key_exprs)} Multisig", script_addrtype, k, key_exprs)
                    msw_id = msw.id
                    if msw_id not in wallets:
                        __, registered_hmac = self._register_policy_if_needed(msw)
                        wallets[msw_id] = (
                            script_addrtype,
                            msw,
                            registered_hmac,
                        )
                else:
                    def process_origin(origin: KeyOriginInfo, *, script_addrtype=script_addrtype) -> None:
                        if is_standard_path(origin.path, script_addrtype, get_chain()):
                            # these policies do not need to be registered
                            policy = self.get_singlesig_default_wallet_policy(script_addrtype, origin.path[2])
                            wallets[policy.id] = (
                                script_addrtype,
                                self.get_singlesig_default_wallet_policy(script_addrtype, origin.path[2]),
                                None,  # Wallet hmac
                            )
                        else:
                            # register the policy
                            if script_addrtype == AddressType.LEGACY:
                                name = "Legacy"
                                template = "pkh(@0/**)"
                            elif script_addrtype == AddressType.WIT:
                                name = "Native SegWit"
                                template = "wpkh(@0/**)"
                            elif script_addrtype == AddressType.SH_WIT:
                                name = "Nested SegWit"
                                template = "sh(wpkh(@0/**))"
                            elif script_addrtype == AddressType.TAP:
                                name = "Taproot"
                                template = "tr(@0/**)"
                            else:
                                raise ValueError("Unknown address type")

                            key_origin_info = origin.to_string()
                            key_origin_steps = key_origin_info.replace('h', '\'').split('/')[1:]
                            if len(key_origin_steps) < 3:
                                # Skip this input, not able to sign
                                return

                            # remove the last two steps
                            account_key_origin = "/".join(key_origin_steps[:-2])

                            # get the account-level xpub
                            xpub = self.get_xpub(f"m/{account_key_origin}", 'standard')
                            key_str = f"[{master_fp.hex()}/{account_key_origin}]{xpub}"

                            policy = WalletPolicy(name, template, [key_str])
                            __, registered_hmac = self.client.register_wallet(policy)
                            wallets[policy.id] = (
                                script_addrtype,
                                policy,
                                registered_hmac,
                            )
                    for key, origin in psbt_in.hd_keypaths.items():
                        if origin.fingerprint == master_fp:
                            process_origin(origin)

                    for key, (__, origin) in psbt_in.tap_bip32_paths.items():
                        # TODO: Support script path signing
                        if key == psbt_in.tap_internal_key and origin.fingerprint == master_fp:
                            process_origin(origin)

            self.handler.show_message(_("Confirm Transaction on your Ledger device..."))

            if len(wallets) == 0:
                # Could not find a WalletPolicy to sign with
                raise UserFacingException(_('Unable to sign this transaction'))

            # For each wallet, sign
            for __, (__, wallet, wallet_hmac) in wallets.items():
                input_sigs = self.client.sign_psbt(psbt, wallet, wallet_hmac)
                for idx, part_sig in input_sigs:
                    tx.add_signature_to_txin(
                        txin_idx=idx, signing_pubkey=part_sig.pubkey, sig=part_sig.signature)
        except DenyError:
            pass  # cancelled by user
        except BaseException as e:
            _logger.exception('Error while signing')
            self.handler.show_error(e)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    @test_pin_unlocked
    def sign_message(
            self,
            address_path: str,
            message: str,
            password,
            *,
            script_type: Optional[str] = None,
    ) -> bytes:
        message = message.encode('utf8')
        message_hash = hashlib.sha256(message).hexdigest().upper()
        # prompt for the PIN before displaying the dialog if necessary
        self.handler.show_message("Signing message ...\r\nMessage hash: " + message_hash)

        result = b''
        try:
            result = base64.b64decode(self.client.sign_message(message, address_path))
        except DenyError:
            pass  # cancelled by user
        except BaseException as e:
            _logger.exception('')
            self.handler.show_error(e)
        finally:
            self.handler.finished()

        return result


class Ledger_KeyStore(Hardware_KeyStore):
    """Ledger keystore. Targets all versions, will have different behavior with different clients."""

    hw_type = 'ledger'
    device = 'Ledger'

    plugin: 'LedgerPlugin'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        self.cfg = d.get('cfg', {'mode': 0})

    def dump(self):
        obj = Hardware_KeyStore.dump(self)
        obj['cfg'] = self.cfg
        return obj

    def get_client_dongle_object(self, *, client: Optional[Ledger_Client] = None) -> Ledger_Client:
        if client is None:
            client = self.get_client()
        return client

    def decrypt_message(self, pubkey, message, password):
        raise UserFacingException(_('Encryption and decryption are currently not supported for {}').format(self.device))

    def sign_message(self, sequence, *args, **kwargs):
        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence
        address_path = normalize_bip32_derivation(address_path, hardened_char="'")
        address_path = address_path[2:]  # cut m/
        return self.get_client_dongle_object().sign_message(address_path, *args, **kwargs)

    def sign_transaction(self, *args, **kwargs):
        return self.get_client_dongle_object().sign_transaction(self, *args, **kwargs)

    def show_address(self, sequence, *args, **kwargs):
        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence
        address_path = normalize_bip32_derivation(address_path, hardened_char="'")
        address_path = address_path[2:]  # cut m/
        return self.get_client_dongle_object().show_address(address_path, *args, **kwargs)


class LedgerPlugin(HW_PluginBase):
    keystore_class = Ledger_KeyStore
    minimum_library = (0, 2, 0)
    maximum_library = (0, 3, 0)
    DEVICE_IDS = [(0x2581, 0x1807),  # HW.1 legacy btchip
                  (0x2581, 0x2b7c),  # HW.1 transitional production
                  (0x2581, 0x3b7c),  # HW.1 ledger production
                  (0x2581, 0x4b7c),  # HW.1 ledger test
                  (0x2c97, 0x0000),  # Blue
                  (0x2c97, 0x0001),  # Nano-S
                  (0x2c97, 0x0004),  # Nano-X
                  (0x2c97, 0x0005),  # Nano-S Plus
                  (0x2c97, 0x0006),  # Stax
                  (0x2c97, 0x0007),  # Flex
                  (0x2c97, 0x0008),  # RFU
                  (0x2c97, 0x0009),  # RFU
                  (0x2c97, 0x000a)]  # RFU
    VENDOR_IDS = (0x2c97,)
    LEDGER_MODEL_IDS = {
        0x10: "Ledger Nano S",
        0x40: "Ledger Nano X",
        0x50: "Ledger Nano S Plus",
        0x60: "Ledger Stax",
        0x70: "Ledger Flex",
    }

    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            _logger.info("Library unavailable")
            return
        # to support legacy devices and legacy firmwares
        self.device_manager().register_devices(self.DEVICE_IDS, plugin=self)
        # to support modern firmware
        self.device_manager().register_vendor_ids(self.VENDOR_IDS, plugin=self)

    def get_library_version(self):
        try:
            import ledger_bitcoin
            version = ledger_bitcoin.__version__
        except ImportError:
            raise
        except Exception:
            version = "unknown"
        if LEDGER_BITCOIN:
            return version
        else:
            raise LibraryFoundButUnusable(library_version=version)

    @classmethod
    def is_hw1(cls, product_key) -> bool:
        return product_key[0] == 0x2581

    @classmethod
    def _recognize_device(cls, product_key) -> Tuple[bool, Optional[str]]:
        """Returns (can_recognize, model_name) tuple."""
        # legacy product_keys
        if product_key in cls.DEVICE_IDS:
            if cls.is_hw1(product_key):
                return True, "Ledger HW.1"
            if product_key == (0x2c97, 0x0000):
                return True, "Ledger Blue"
            if product_key == (0x2c97, 0x0001):
                return True, "Ledger Nano S"
            if product_key == (0x2c97, 0x0004):
                return True, "Ledger Nano X"
            if product_key == (0x2c97, 0x0005):
                return True, "Ledger Nano S Plus"
            if product_key == (0x2c97, 0x0006):
                return True, "Ledger Stax"
            if product_key == (0x2c97, 0x0007):
                return True, "Ledger Flex"
            return True, None
        # modern product_keys
        if product_key[0] == 0x2c97:
            product_id = product_key[1]
            model_id = product_id >> 8
            if model_id in cls.LEDGER_MODEL_IDS:
                model_name = cls.LEDGER_MODEL_IDS[model_id]
                return True, model_name
        # give up
        return False, None

    def can_recognize_device(self, device: Device) -> bool:
        can_recognize = self._recognize_device(device.product_key)[0]
        if can_recognize:
            # Do a further check, duplicated from:
            # https://github.com/LedgerHQ/ledgercomm/blob/bc5ada865980cb63c2b9b71a916e01f2f8e53716/ledgercomm/interfaces/hid_device.py#L79-L82
            # Modern ledger devices can have multiple interfaces picked up by hid, only one of which is usable by us.
            # If we try communicating with the wrong one, we might not get a reply and block forever.
            if device.product_key[0] == 0x2c97:
                if not (device.interface_number == 0 or device.usage_page == 0xffa0):
                    return False
        return can_recognize

    @classmethod
    def device_name_from_product_key(cls, product_key) -> Optional[str]:
        return cls._recognize_device(product_key)[1]

    def create_device_from_hid_enumeration(self, d, *, product_key):
        device = super().create_device_from_hid_enumeration(d, product_key=product_key)
        if not self.can_recognize_device(device):
            return None
        return device

    @runs_in_hwd_thread
    def create_client(self, device, handler) -> Optional[Ledger_Client]:
        try:
            return Ledger_Client.construct_new(device=device, product_key=device.product_key, plugin=self)
        except Exception as e:
            self.logger.info(f"cannot connect at {device.path} {e}", exc_info=e)
        return None

    @runs_in_hwd_thread
    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        if type(wallet) is not Standard_Wallet:
            keystore.handler.show_error(_('This function is only available for standard wallets when using {}.').format(self.device))
            return
        sequence = wallet.get_address_index(address)
        txin_type = wallet.get_txin_type(address)

        keystore.show_address(sequence, txin_type)

    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet=True) -> str:
        if new_wallet:
            return 'ledger_start' if device_info.initialized else 'ledger_not_initialized'
        else:
            return 'ledger_unlock'

    # insert ledger pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'ledger_start': {
                'next': 'ledger_xpub',
            },
            'ledger_xpub': {
                'next': lambda d: wizard.wallet_password_view(d) if wizard.last_cosigner(d) else 'multisig_cosigner_keystore',
                'accept': wizard.maybe_master_pubkey,
                'last': lambda d: wizard.is_single_password() and wizard.last_cosigner(d)
            },
            'ledger_not_initialized': {},
            'ledger_unlock': {
                'last': True
            },
        }
        wizard.navmap_merge(views)

