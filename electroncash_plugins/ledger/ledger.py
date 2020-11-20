from struct import pack, unpack
import hashlib
import sys
import traceback
import inspect

from electroncash import bitcoin
from electroncash.address import Address, OpCodes
from electroncash.bitcoin import TYPE_ADDRESS, TYPE_SCRIPT, int_to_hex, var_int
from electroncash.i18n import _
from electroncash.plugins import BasePlugin
from electroncash.keystore import Hardware_KeyStore
from electroncash.transaction import Transaction
from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch, validate_op_return_output_and_get_data
from electroncash.util import print_error, is_verbose, bfh, bh2u, versiontuple

try:
    import hid
    from btchip.btchipComm import HIDDongleHIDAPI, DongleWait
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script, get_p2sh_input_script
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipFirmwareWizard import checkFirmware, updateFirmware
    from btchip.btchipException import BTChipException
    BTCHIP = True
    BTCHIP_DEBUG = is_verbose
except ImportError:
    BTCHIP = False

MSG_NEEDS_FW_UPDATE_CASHADDR = _('Firmware version (or "Bitcoin Cash" app) too old for CashAddr support. ') + \
                               _('Please update at https://www.ledgerwallet.com')
MSG_NEEDS_SW_UPDATE_CASHADDR = _('python-btchip is too old for CashAddr support. ') + \
                               _('Please update to v0.1.27 or greater')
BITCOIN_CASH_SUPPORT_HW1 = (1, 0, 4)
BITCOIN_CASH_SUPPORT = (1, 1, 8)
CASHADDR_SUPPORT = (1, 2, 5)
MULTI_OUTPUT_SUPPORT = (1, 1, 4)
TRUSTED_INPUTS_REQUIRED = (1, 4, 0)

def test_pin_unlocked(func):
    """Function decorator to test the Ledger for being unlocked, and if not,
    raise a human-readable exception.
    """
    def catch_exception(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except BTChipException as e:
            if e.sw in (0x6982, 0x6f04):
                raise Exception(_('Your {} is locked. Please unlock it.').format(self.device) + '\n\n' + _('After unlocking, may also need to re-open this wallet window as well.')) from e
            else:
                raise
    return catch_exception

class Ledger_Client:

    def __init__(self, plugin, hidDevice, isHW1=False):
        self.device = plugin.device
        self.dongleObject = btchip(hidDevice)
        self.preflightDone = False
        self.isHW1 = isHW1

    def is_pairable(self):
        return True

    def close(self):
        self.dongleObject.dongle.close()

    def timeout(self, cutoff):
        pass

    def is_initialized(self):
        return True

    def label(self):
        return ""

    def is_hw1(self):
        return self.isHW1

    def i4b(self, x):
        return pack('>I', x)

    def has_usable_connection_with_device(self):
        try:
            self.dongleObject.getFirmwareVersion()
        except BTChipException as e:
            if e.sw == 0x6700:
                # When Ledger is in the app selection menu, getting the firmware version results
                # in 0x6700 being returned. Getting an error code back means we can actually
                # communicate with the device, so we return True here.
                return True
            return False
        except BaseException:
            return False
        return True

    @test_pin_unlocked
    def get_xpub(self, bip32_path, xtype):
        self.checkDevice()
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        #self.get_client() # prompt for the PIN before displaying the dialog if necessary
        #self.handler.show_message("Computing master public key")
        splitPath = bip32_path.split('/')
        if splitPath[0] == 'm':
            splitPath = splitPath[1:]
            bip32_path = bip32_path[2:]
        fingerprint = 0
        if len(splitPath) > 1:
            prevPath = "/".join(splitPath[0:len(splitPath) - 1])
            nodeData = self.dongleObject.getWalletPublicKey(prevPath)
            publicKey = compress_public_key(nodeData['publicKey'])
            h = hashlib.new('ripemd160')
            h.update(hashlib.sha256(publicKey).digest())
            fingerprint = unpack(">I", h.digest()[0:4])[0]
        nodeData = self.dongleObject.getWalletPublicKey(bip32_path)
        publicKey = compress_public_key(nodeData['publicKey'])
        depth = len(splitPath)
        lastChild = splitPath[len(splitPath) - 1].split('\'')
        childnum = int(lastChild[0]) if len(lastChild) == 1 else 0x80000000 | int(lastChild[0])
        xpub = bitcoin.serialize_xpub(xtype, nodeData['chainCode'], publicKey, depth, self.i4b(fingerprint), self.i4b(childnum))
        return xpub

    def has_detached_pin_support(self, client):
        try:
            client.getVerifyPinRemainingAttempts()
            return True
        except BTChipException as e:
            if e.sw == 0x6d00:
                return False
            raise e

    def is_pin_validated(self, client):
        try:
            # Invalid SET OPERATION MODE to verify the PIN status
            client.dongle.exchange(bytearray([0xe0, 0x26, 0x00, 0x00, 0x01, 0xAB]))
        except BTChipException as e:
            if (e.sw == 0x6982):
                return False
            if (e.sw == 0x6A80):
                return True
            raise e

    def supports_bitcoin_cash(self):
        return self.bitcoinCashSupported

    def fw_supports_cashaddr(self):
        return self.cashaddrFWSupported

    def sw_supports_cashaddr(self):
        return self.cashaddrSWSupported

    def supports_cashaddr(self):
        return self.fw_supports_cashaddr() and self.sw_supports_cashaddr()

    def supports_multi_output(self):
        return self.multiOutputSupported

    def requires_trusted_inputs(self):
        return self.trustedInputsRequired

    def perform_hw1_preflight(self):
        try:
            firmwareInfo = self.dongleObject.getFirmwareVersion()
            firmwareVersion = versiontuple(firmwareInfo['version'])
            self.bitcoinCashSupported = firmwareVersion >= BITCOIN_CASH_SUPPORT or \
                self.is_hw1() and firmwareVersion >= BITCOIN_CASH_SUPPORT_HW1
            self.cashaddrFWSupported = firmwareVersion >= CASHADDR_SUPPORT
            self.multiOutputSupported = firmwareVersion >= MULTI_OUTPUT_SUPPORT
            self.trustedInputsRequired = firmwareVersion >= TRUSTED_INPUTS_REQUIRED

            if not checkFirmware(firmwareInfo) or not self.supports_bitcoin_cash():
                self.dongleObject.dongle.close()
                raise Exception(_("{} firmware version too old. Please update at https://www.ledgerwallet.com").format(self.device))
            try:
                self.dongleObject.getOperationMode()
            except BTChipException as e:
                if (e.sw == 0x6985):
                    self.dongleObject.dongle.close()
                    self.handler.get_setup( )
                    # Acquire the new client on the next run
                else:
                    raise e
            if self.has_detached_pin_support(self.dongleObject) and not self.is_pin_validated(self.dongleObject) and (self.handler is not None):
                remaining_attempts = self.dongleObject.getVerifyPinRemainingAttempts()
                if remaining_attempts != 1:
                    msg = _('Enter your {} PIN - remaining attempts: {}').format(self.device, remaining_attempts)
                else:
                    msg = _('Enter your {} PIN - WARNING: LAST ATTEMPT. If the PIN is not correct, the {} will be wiped.').format(self.device, self.device)
                confirmed, p, pin = self.password_dialog(msg)
                if not confirmed:
                    raise Exception(_('Aborted by user - please unplug the {hw_device_name} and plug it in again before retrying').format(hw_device_name=self.device))
                pin = pin.encode()
                self.dongleObject.verifyPin(pin)

            gwpkArgSpecs = inspect.getfullargspec(self.dongleObject.getWalletPublicKey)
            self.cashaddrSWSupported = 'cashAddr' in gwpkArgSpecs.args
        except BTChipException as e:
            if (e.sw == 0x6faa):
                raise Exception(_("{hw_device_name} is temporarily locked - please unplug and plug it in again."
                                  "\n\nIf this problem persists please exit and restart the Bitcoin Cash "
                                  "application running on the device.\n\nYou may also need to re-open this "
                                  "wallet window as well.").format(hw_device_name=self.device)) from e
            if ((e.sw & 0xFFF0) == 0x63c0):
                raise Exception(_('Invalid PIN - please unplug the {hw_device_name} and plug it in again before retrying').format(hw_device_name=self.device)) from e
            if e.sw == 0x6f00 and e.message == 'Invalid channel':
                # based on docs 0x6f00 might be a more general error, hence we also compare message to be sure
                raise Exception(_('Invalid channel.') + '\n' +
                                _('Please make sure that \'Browser support\' is disabled on your {}.').format(self.device)) from e
            raise e

    def checkDevice(self):
        if not self.preflightDone:
            try:
                self.perform_hw1_preflight()
            except BTChipException as e:
                if (e.sw == 0x6d00 or e.sw == 0x6700):
                    raise BaseException(_('{} not in Bitcoin Cash mode').format(self.device)) from e
                raise e
            self.preflightDone = True

    def password_dialog(self, msg=None):
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response


class Ledger_KeyStore(Hardware_KeyStore):
    hw_type = 'ledger'
    device = 'Ledger'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.force_watching_only = False
        self.signing = False
        self.cfg = d.get('cfg', {'mode':0})

    def dump(self):
        obj = Hardware_KeyStore.dump(self)
        obj['cfg'] = self.cfg
        return obj

    def get_derivation(self):
        return self.derivation

    def get_client(self):
        return self.plugin.get_client(self).dongleObject

    def get_client_electrum(self):
        return self.plugin.get_client(self)

    def give_error(self, message, clear_client = False):
        print_error(message)
        if not self.signing:
            self.handler.show_error(message)
        else:
            self.signing = False
        if clear_client:
            self.client = None
        raise Exception(message)

    def set_and_unset_signing(func):
        """Function decorator to set and unset self.signing."""
        def wrapper(self, *args, **kwargs):
            try:
                self.signing = True
                return func(self, *args, **kwargs)
            finally:
                self.signing = False
        return wrapper

    def cashaddr_alert(self):
        """Alert users about fw/sw updates for cashaddr."""
        if Address.FMT_UI == Address.FMT_CASHADDR:
            # Do not warn if the device is HW1, they have no display anyway
            if not self.get_client_electrum().fw_supports_cashaddr() and not self.get_client_electrum().is_hw1():
                self.handler.show_warning(MSG_NEEDS_FW_UPDATE_CASHADDR)
            if not self.get_client_electrum().sw_supports_cashaddr():
                self.handler.show_warning(MSG_NEEDS_SW_UPDATE_CASHADDR)

    def address_id_stripped(self, address):
        # Strip the leading "m/"
        change, index = self.get_address_index(address)
        derivation = self.derivation
        address_path = "{:s}/{:d}/{:d}".format(derivation, change, index)
        return address_path[2:]

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Encryption and decryption are currently not supported for {}').format(self.device))

    @test_pin_unlocked
    @set_and_unset_signing
    def sign_message(self, sequence, message, password):
        message = message.encode('utf8')
        message_hash = hashlib.sha256(message).hexdigest().upper()
        # prompt for the PIN before displaying the dialog if necessary
        client = self.get_client()
        address_path = self.get_derivation()[2:] + "/{:d}/{:d}".format(*sequence)
        self.handler.show_message(_('Signing message...') + '\n' +
                                  _('Message hash: {}').format(message_hash))
        try:
            info = self.get_client().signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                pin = self.handler.get_auth( info ) # does the authenticate dialog and returns pin
                if not pin:
                    raise UserWarning(_('Cancelled by user'))
                pin = str(pin).encode()
            signature = self.get_client().signMessageSign(pin)
        except BTChipException as e:
            if e.sw == 0x6a80:
                self.give_error(_('Unfortunately, this message cannot be signed by the {}. Only alphanumerical messages shorter than 140 characters are supported. Please remove any extra characters (tab, carriage return) and retry.').format(self.device))
            elif e.sw == 0x6985:  # cancelled by user
                return b''
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            else:
                self.give_error(e, True)
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return b''
        except Exception as e:
            self.give_error(e, True)
        finally:
            self.handler.finished()
        # Parse the ASN.1 signature
        rLength = signature[3]
        r = signature[4 : 4 + rLength]
        sLength = signature[4 + rLength + 1]
        s = signature[4 + rLength + 2:]
        if rLength == 33:
            r = r[1:]
        if sLength == 33:
            s = s[1:]
        # And convert it
        return bytes([27 + 4 + (signature[0] & 0x01)]) + r + s

    @test_pin_unlocked
    @set_and_unset_signing
    def sign_transaction(self, tx, password, *, use_cache=False):
        if tx.is_complete():
            return
        client = self.get_client()
        inputs = []
        inputsPaths = []
        pubKeys = []
        chipInputs = []
        redeemScripts = []
        signatures = []
        preparedTrustedInputs = []
        changePath = ""
        output = None
        p2shTransaction = False
        pin = ""
        self.get_client() # prompt for the PIN before displaying the dialog if necessary
        self.cashaddr_alert()

        # Fetch inputs of the transaction to sign
        derivations = self.get_tx_derivations(tx)
        for txin in tx.inputs():
            if txin['type'] == 'coinbase':
                self.give_error(_('Coinbase not supported')) # should never happen

            if txin['type'] in ['p2sh']:
                p2shTransaction = True

            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            for i, x_pubkey in enumerate(x_pubkeys):
                if x_pubkey in derivations:
                    signingPos = i
                    s = derivations.get(x_pubkey)
                    hwAddress = "{:s}/{:d}/{:d}".format(self.get_derivation()[2:], s[0], s[1])
                    break
            else:
                self.give_error(_('No matching x_key for sign_transaction')) # should never happen

            redeemScript = Transaction.get_preimage_script(txin)
            inputs.append([txin['prev_tx'].raw, txin['prevout_n'], redeemScript, txin['prevout_hash'], signingPos, txin.get('sequence', 0xffffffff - 1) ])
            inputsPaths.append(hwAddress)
            pubKeys.append(pubkeys)

        # Sanity check
        if p2shTransaction:
            for txin in tx.inputs():
                if txin['type'] != 'p2sh':
                    self.give_error(_('P2SH / regular input mixed in same transaction not supported')) # should never happen

        txOutput = var_int(len(tx.outputs()))
        for txout in tx.outputs():
            output_type, addr, amount = txout
            txOutput += int_to_hex(amount, 8)
            script = tx.pay_script(addr)
            txOutput += var_int(len(script)//2)
            txOutput += script
        txOutput = bfh(txOutput)

        # Recognize outputs
        # - only one output and one change is authorized (for hw.1 and nano)
        # - at most one output can bypass confirmation (~change) (for all)
        if not p2shTransaction:
            if not self.get_client_electrum().supports_multi_output():
                if len(tx.outputs()) > 2:
                    self.give_error(_('Transaction with more than 2 outputs not supported by {}').format(self.device))
            has_change = False
            any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)
            for o in tx.outputs():
                _type, address, amount = o
                if self.get_client_electrum().is_hw1():
                    if not _type == TYPE_ADDRESS:
                        self.give_error(_('Only address outputs are supported by {}').format(self.device))
                else:
                    if not _type in [TYPE_ADDRESS, TYPE_SCRIPT]:
                        self.give_error(_('Only address and script outputs are supported by {}').format(self.device))
                    if _type == TYPE_SCRIPT:
                        try:
                            # Ledger has a maximum output size of 200 bytes:
                            # https://github.com/LedgerHQ/ledger-app-btc/commit/3a78dee9c0484821df58975803e40d58fbfc2c38#diff-c61ccd96a6d8b54d48f54a3bc4dfa7e2R26
                            # which gives us a maximum OP_RETURN payload size of
                            # 187 bytes. It also apparently has no limit on
                            # max_pushes, so we specify max_pushes=None so as
                            # to bypass that check.
                            validate_op_return_output_and_get_data(o, max_size=187, max_pushes=None)
                        except RuntimeError as e:
                            self.give_error('{}: {}'.format(self.device, str(e)))
                info = tx.output_info.get(address)
                if (info is not None) and len(tx.outputs()) > 1 \
                        and not has_change:
                    index, xpubs, m, script_type = info
                    on_change_branch = index[0] == 1
                    # prioritise hiding outputs on the 'change' branch from user
                    # because no more than one change address allowed
                    if on_change_branch == any_output_on_change_branch:
                        changePath = self.get_derivation()[2:] + "/{:d}/{:d}".format(*index)
                        has_change = True
                    else:
                        output = address
                else:
                    output = address

        self.handler.show_message(_('Confirm Transaction on your {}...').format(self.device))
        try:
            # Get trusted inputs from the original transactions
            for utxo in inputs:
                sequence = int_to_hex(utxo[5], 4)
                if not self.get_client_electrum().requires_trusted_inputs():
                    txtmp = bitcoinTransaction(bfh(utxo[0]))
                    tmp = bfh(utxo[3])[::-1]
                    tmp += bfh(int_to_hex(utxo[1], 4))
                    tmp += txtmp.outputs[utxo[1]].amount
                    chipInputs.append({'value' : tmp, 'witness' : True, 'sequence' : sequence})
                    redeemScripts.append(bfh(utxo[2]))
                else:
                    txtmp = bitcoinTransaction(bfh(utxo[0]))
                    trustedInput = self.get_client().getTrustedInput(txtmp, utxo[1])
                    trustedInput['sequence'] = sequence
                    trustedInput['witness'] = True
                    chipInputs.append(trustedInput)
                    if p2shTransaction:
                        redeemScripts.append(bfh(utxo[2]))
                    else:
                        redeemScripts.append(txtmp.outputs[utxo[1]].script)

            # Sign all inputs
            inputIndex = 0
            self.get_client().enableAlternate2fa(False)
            cashaddr = Address.FMT_UI == Address.FMT_CASHADDR
            if cashaddr and self.get_client_electrum().supports_cashaddr():
                self.get_client().startUntrustedTransaction(True, inputIndex, chipInputs,
                                                            redeemScripts[inputIndex], cashAddr=True)
            else:
                self.get_client().startUntrustedTransaction(True, inputIndex,
                                                            chipInputs, redeemScripts[inputIndex])
            # we don't set meaningful outputAddress, amount and fees
            # as we only care about the alternateEncoding==True branch
            outputData = self.get_client().finalizeInput(b'', 0, 0, changePath, bfh(tx.serialize(True)))
            outputData['outputData'] = txOutput
            transactionOutput = outputData['outputData']
            if outputData['confirmationNeeded']:
                outputData['address'] = output
                self.handler.finished()
                pin = self.handler.get_auth( outputData ) # does the authenticate dialog and returns pin
                if not pin:
                    raise UserWarning()
                self.handler.show_message(_('Confirmed. Signing Transaction...'))
            while inputIndex < len(inputs):
                singleInput = [ chipInputs[inputIndex] ]
                if cashaddr and self.get_client_electrum().supports_cashaddr():
                    self.get_client().startUntrustedTransaction(False, 0, singleInput,
                                                            redeemScripts[inputIndex], cashAddr=True)
                else:
                    self.get_client().startUntrustedTransaction(False, 0,
                                                            singleInput, redeemScripts[inputIndex])
                inputSignature = self.get_client().untrustedHashSign(inputsPaths[inputIndex], pin, lockTime=tx.locktime, sighashType=0x41)
                inputSignature[0] = 0x30 # force for 1.4.9+
                signatures.append(inputSignature)
                inputIndex = inputIndex + 1
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return
        except BTChipException as e:
            if e.sw in (0x6985, 0x6d00):  # cancelled by user
                return
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            else:
                traceback.print_exc(file=sys.stderr)
                self.give_error(e, True)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.give_error(e, True)
        finally:
            self.handler.finished()

        for i, txin in enumerate(tx.inputs()):
            signingPos = inputs[i][4]
            txin['signatures'][signingPos] = bh2u(signatures[i])
        tx.raw = tx.serialize()

    @test_pin_unlocked
    @set_and_unset_signing
    def show_address(self, sequence):
        client = self.get_client()
        # prompt for the PIN before displaying the dialog if necessary
        address_path = self.get_derivation()[2:] + "/{:d}/{:d}".format(*sequence)
        self.cashaddr_alert()
        self.handler.show_message(_('Showing address on {}...').format(self.device))
        try:
            if Address.FMT_UI == Address.FMT_CASHADDR and self.get_client_electrum().supports_cashaddr():
                client.getWalletPublicKey(address_path, showOnScreen=True, cashAddr=True)
            else:
                client.getWalletPublicKey(address_path, showOnScreen=True)
        except BTChipException as e:
            if e.sw == 0x6985:  # cancelled by user
                pass
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            elif e.sw == 0x6b00:  # hw.1 raises this
                self.handler.show_error('{}\n{}\n{}'.format(
                    _('Error showing address') + ':',
                    e,
                    _('Your {} might not have support for this functionality.').format(self.device)))
            else:
                traceback.print_exc(file=sys.stderr)
                self.handler.show_error(e)
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.handler.show_error(e)
        finally:
            self.handler.finished()


class LedgerPlugin(HW_PluginBase):
    libraries_available = BTCHIP
    keystore_class = Ledger_KeyStore
    client = None
    DEVICE_IDS = [
                   (0x2581, 0x1807), # HW.1 legacy btchip
                   (0x2581, 0x2b7c), # HW.1 transitional production
                   (0x2581, 0x3b7c), # HW.1 ledger production
                   (0x2581, 0x4b7c), # HW.1 ledger test
                   (0x2c97, 0x0000), # Blue
                   (0x2c97, 0x0011), # Blue app-bitcoin >= 1.5.1
                   (0x2c97, 0x0015), # Blue app-bitcoin >= 1.5.1
                   (0x2c97, 0x0001), # Nano-S
                   (0x2c97, 0x1011), # Nano-S app-bitcoin >= 1.5.1
                   (0x2c97, 0x1015), # Nano-S app-bitcoin >= 1.5.1
                   (0x2c97, 0x0004), # Nano-X
                   (0x2c97, 0x4011), # Nano-X app-bitcoin >= 1.5.1
                   (0x2c97, 0x4015), # Nano-X app-bitcoin >= 1.5.1
                 ]

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        if self.libraries_available:
            self.device_manager().register_devices(self.DEVICE_IDS)

    def get_btchip_device(self, device):
        ledger = False
        if device.product_key[0] == 0x2581 and device.product_key[1] == 0x3b7c:
            ledger = True
        if device.product_key[0] == 0x2581 and device.product_key[1] == 0x4b7c:
            ledger = True
        if device.product_key[0] == 0x2c97:
            if device.interface_number == 0 or device.usage_page == 0xffa0:
                ledger = True
            else:
                return None  # non-compatible interface of a nano s or blue
        dev = hid.device()
        dev.open_path(device.path)
        dev.set_nonblocking(True)
        return HIDDongleHIDAPI(dev, ledger, BTCHIP_DEBUG)

    def create_client(self, device, handler):
        self.handler = handler

        client = self.get_btchip_device(device)
        ishw1 = device.product_key[0] == 0x2581
        if client is not None:
            client = Ledger_Client(self, client, ishw1)
        return client

    def setup_device(self, device_info, wizard):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            # BaseWizard expects this Exception to re-try
            raise OSError(_('Device id not found or was changed'))
        client.handler = self.create_handler(wizard)
        client.get_xpub("m/44'/0'", 'standard') # TODO replace by direct derivation once Nano S > 1.1

    def get_xpub(self, device_id, derivation, xtype, wizard):
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        client.checkDevice()
        xpub = client.get_xpub(derivation, xtype)
        return xpub

    def get_client(self, keystore, force_pair=True):
        # All client interaction should not be in the main GUI thread
        #assert self.main_thread != threading.current_thread()
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        # returns the client for a given keystore. can use xpub
        #if client:
        #    client.used()
        if client is not None:
            client.checkDevice()
        return client

    def show_address(self, wallet, address):
        sequence = wallet.get_address_index(address)
        wallet.get_keystore().show_address(sequence)
