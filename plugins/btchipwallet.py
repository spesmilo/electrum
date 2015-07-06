from PyQt4.Qt import QApplication, QMessageBox, QDialog, QInputDialog, QLineEdit, QVBoxLayout, QLabel, QThread, SIGNAL
import PyQt4.QtCore as QtCore
from binascii import unhexlify
from binascii import hexlify
from struct import pack,unpack
from sys import stderr
from time import sleep
from base64 import b64encode, b64decode

import electrum_ltc as electrum
from electrum_ltc_gui.qt.password_dialog import make_password_dialog, run_password_dialog
from electrum_ltc.account import BIP32_Account
from electrum_ltc.bitcoin import EncodeBase58Check, DecodeBase58Check, public_key_to_bc_address, bc_address_to_hash_160, hash_160_to_bc_address
from electrum_ltc.i18n import _
from electrum_ltc.plugins import BasePlugin, hook
from electrum_ltc.transaction import deserialize
from electrum_ltc.wallet import BIP32_HD_Wallet, BIP32_Wallet

from electrum_ltc.util import format_satoshis_plain, print_error, print_msg
import hashlib
import threading

def setAlternateCoinVersions(self, regular, p2sh):
    apdu = [ self.BTCHIP_CLA, 0x14, 0x00, 0x00, 0x02, regular, p2sh ]
    self.dongle.exchange(bytearray(apdu))

try:
    from btchip.btchipComm import getDongle, DongleWait
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipPersoWizard import StartBTChipPersoDialog
    from btchip.btchipFirmwareWizard import checkFirmware, updateFirmware
    from btchip.btchipException import BTChipException
    btchip.setAlternateCoinVersions = setAlternateCoinVersions
    BTCHIP = True
    BTCHIP_DEBUG = False
except ImportError:
    BTCHIP = False

class Plugin(BasePlugin):

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()
        self.wallet = None
        self.handler = None

    def constructor(self, s):
        return BTChipWallet(s)

    def _init(self):
        return BTCHIP

    def is_available(self):
        if not self._is_available:
            return False
        if not self.wallet:
            return False
        if self.wallet.storage.get('wallet_type') != 'btchip':
            return False
        return True

    def set_enabled(self, enabled):
        self.wallet.storage.put('use_' + self.name, enabled)

    def is_enabled(self):
        if not self.is_available():
            return False
        if self.wallet.has_seed():
            return False
        return True

    def btchip_is_connected(self):
        try:
            self.wallet.get_client().getFirmwareVersion()
        except:
            return False
        return True

    @hook
    def cmdline_load_wallet(self, wallet):
        self.wallet = wallet
        self.wallet.plugin = self
        if self.handler is None:
            self.handler = BTChipCmdLineHandler()

    @hook
    def load_wallet(self, wallet, window):
        self.wallet = wallet
        self.wallet.plugin = self
        self.window = window
        if self.handler is None:
            self.handler = BTChipQTHandler(self.window.app)
        if self.btchip_is_connected():
            if not self.wallet.check_proper_device():
                QMessageBox.information(self.window, _('Error'), _("This wallet does not match your BTChip device"), _('OK'))
                self.wallet.force_watching_only = True
        else:
            QMessageBox.information(self.window, _('Error'), _("BTChip device not detected.\nContinuing in watching-only mode."), _('OK'))
            self.wallet.force_watching_only = True

    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != 'btchip':
            return
        wallet = BTChipWallet(storage)
        try:
            wallet.create_main_account(None)
        except BaseException as e:
            QMessageBox.information(None, _('Error'), str(e), _('OK'))
            return
        return wallet

    @hook
    def sign_tx(self, tx):
        tx.error = None
        try:
            self.wallet.sign_transaction(tx, None)
        except Exception as e:
            tx.error = str(e)

class BTChipWallet(BIP32_HD_Wallet):
    wallet_type = 'btchip'
    root_derivation = "m/44'/2'"

    def __init__(self, storage):
        BIP32_HD_Wallet.__init__(self, storage)
        self.transport = None
        self.client = None
        self.mpk = None
        self.device_checked = False
        self.signing = False
        self.force_watching_only = False

    def give_error(self, message, clear_client = False):
        print_error(message)
        if not self.signing:
            QMessageBox.warning(QDialog(), _('Warning'), _(message), _('OK'))
        else:
            self.signing = False
        if clear_client and self.client is not None:
            self.client.bad = True
            self.device_checked = False
        raise Exception(message)

    def get_action(self):
        if not self.accounts:
            return 'create_accounts'

    def can_sign_xpubkey(self, x_pubkey):
        xpub, sequence = BIP32_Account.parse_xpubkey(x_pubkey)
        return xpub in self.master_public_keys.values()

    def can_create_accounts(self):
        return False

    def synchronize(self):
        # synchronize existing accounts
        BIP32_Wallet.synchronize(self)
        # no further accounts for the moment

    def can_change_password(self):
        return False

    def is_watching_only(self):
        return self.force_watching_only

    def get_client(self, noPin=False):
        if not BTCHIP:
            self.give_error('please install github.com/btchip/btchip-python')

        aborted = False
        if not self.client or self.client.bad:
            try:   
                d = getDongle(BTCHIP_DEBUG)
                self.client = btchip(d)
                self.client.handler = self.plugin.handler                
                ver = self.client.getFirmwareVersion()
                firmware = ver['version'].split(".")
                self.canAlternateCoinVersions = (ver['specialVersion'] >= 0x20 and
                                                 map(int, firmware) >= [1, 0, 1])
                if not checkFirmware(firmware):
                    d.close()
                    try:
                        updateFirmware()
                    except Exception, e:
                        aborted = True
                        raise e
                    d = getDongle(BTCHIP_DEBUG)
                    self.client = btchip(d)
                try:
                    self.client.getOperationMode()
                except BTChipException, e:
                    if (e.sw == 0x6985):
                        d.close()
                        dialog = StartBTChipPersoDialog()
                        dialog.exec_()
                        # Then fetch the reference again  as it was invalidated
                        d = getDongle(BTCHIP_DEBUG)
                        self.client = btchip(d)
                    else:
                        raise e
                if not noPin:
                    # Immediately prompts for the PIN
                    remaining_attempts = self.client.getVerifyPinRemainingAttempts()
                    if remaining_attempts <> 1:
                        msg = "Enter your BTChip PIN - remaining attempts : " + str(remaining_attempts)
                    else:
                        msg = "Enter your BTChip PIN - WARNING : LAST ATTEMPT. If the PIN is not correct, the dongle will be wiped."
                    confirmed, p, pin = self.password_dialog(msg)
                    if not confirmed:
                        aborted = True
                        raise Exception('Aborted by user - please unplug the dongle and plug it again before retrying')
                    pin = pin.encode()
                    self.client.verifyPin(pin)
                    if self.canAlternateCoinVersions:
                        self.client.setAlternateCoinVersions(48, 5)

            except BTChipException, e:
                try:
                    self.client.dongle.close()
                except:
                    pass
                self.client = None
                if (e.sw == 0x6faa):
                    raise Exception("Dongle is temporarily locked - please unplug it and replug it again")
                if ((e.sw & 0xFFF0) == 0x63c0):
                    raise Exception("Invalid PIN - please unplug the dongle and plug it again before retrying")
                raise e
            except Exception, e:
                try:
                    self.client.dongle.close()
                except:
                    pass
                self.client = None
                if not aborted:
                    raise Exception("Could not connect to your BTChip dongle. Please verify access permissions, PIN, or unplug the dongle and plug it again")
                else:
                    raise e
            self.client.bad = False
            self.device_checked = False
            self.proper_device = False
        return self.client

    def address_id(self, address):
        account_id, (change, address_index) = self.get_address_index(address)
        return "44'/2'/%s'/%d/%d" % (account_id, change, address_index)

    def create_main_account(self, password):
        self.create_account('Main account', None) #name, empty password

    def derive_xkeys(self, root, derivation, password):
        derivation = derivation.replace(self.root_name,"44'/2'/")
        xpub = self.get_public_key(derivation)
        return xpub, None

    def get_private_key(self, address, password):
        return []

    def get_public_key(self, bip32_path):
        # S-L-O-W - we don't handle the fingerprint directly, so compute it manually from the previous node
        # This only happens once so it's bearable
        self.get_client() # prompt for the PIN before displaying the dialog if necessary
        self.plugin.handler.show_message("Computing master public key")
        try:
            splitPath = bip32_path.split('/')
            fingerprint = 0
            if len(splitPath) > 1:
                prevPath = "/".join(splitPath[0:len(splitPath) - 1])
                nodeData = self.get_client().getWalletPublicKey(prevPath)
                publicKey = compress_public_key(nodeData['publicKey'])
                h = hashlib.new('ripemd160')
                h.update(hashlib.sha256(publicKey).digest())
                fingerprint = unpack(">I", h.digest()[0:4])[0]
            nodeData = self.get_client().getWalletPublicKey(bip32_path)
            publicKey = compress_public_key(nodeData['publicKey'])
            depth = len(splitPath)
            lastChild = splitPath[len(splitPath) - 1].split('\'')
            if len(lastChild) == 1:
                childnum = int(lastChild[0])
            else:
                childnum = 0x80000000 | int(lastChild[0])
            xpub = "0488B21E".decode('hex') + chr(depth) + self.i4b(fingerprint) + self.i4b(childnum) + str(nodeData['chainCode']) + str(publicKey)
        except Exception, e:
            self.give_error(e, True)
        finally:
            self.plugin.handler.stop()

        return EncodeBase58Check(xpub)

    def get_master_public_key(self):
        try:
            if not self.mpk:
                self.mpk = self.get_public_key("44'/2'")
            return self.mpk
        except Exception, e:
            self.give_error(e, True)

    def i4b(self, x):
        return pack('>I', x)

    def add_keypairs(self, tx, keypairs, password):
        #do nothing - no priv keys available
        pass

    def decrypt_message(self, pubkey, message, password):
        self.give_error("Not supported")

    def sign_message(self, address, message, password):
        use2FA = False
        self.signing = True
        self.get_client() # prompt for the PIN before displaying the dialog if necessary
        if not self.check_proper_device():
            self.give_error('Wrong device or password')
        address_path = self.address_id(address)
        self.plugin.handler.show_message("Signing message ...")
        try:
            info = self.get_client().signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                # TODO : handle different confirmation types. For the time being only supports keyboard 2FA
                use2FA = True
                confirmed, p, pin = self.password_dialog()
                if not confirmed:
                    raise Exception('Aborted by user')
                pin = pin.encode()
                self.client.bad = True
                self.device_checked = False
                self.get_client(True)
            signature = self.get_client().signMessageSign(pin)
        except BTChipException, e:
            if e.sw == 0x6a80:
                self.give_error("Unfortunately, this message cannot be signed by BTChip. Only alphanumerical messages shorter than 140 characters are supported. Please remove any extra characters (tab, carriage return) and retry.")
            else:
                self.give_error(e, True)
        except Exception, e:
            self.give_error(e, True)
        finally:
            self.plugin.handler.stop()
        self.client.bad = use2FA
        self.signing = False

        # Parse the ASN.1 signature

        rLength = signature[3]
        r = signature[4 : 4 + rLength]
        sLength = signature[4 + rLength + 1]
        s = signature[4 + rLength + 2:]
        if rLength == 33:
            r = r[1:]
        if sLength == 33:
            s = s[1:]
        r = str(r)
        s = str(s)

        # And convert it

        return b64encode(chr(27 + 4 + (signature[0] & 0x01)) + r + s)

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        #if tx.error:
        #    raise BaseException(tx.error)
        self.signing = True
        inputs = []
        inputsPaths = []
        pubKeys = []
        trustedInputs = []
        redeemScripts = []
        signatures = []
        preparedTrustedInputs = []
        changePath = ""
        changeAmount = None
        output = None
        outputAmount = None
        use2FA = False
        pin = ""
        rawTx = tx.serialize()
        # Fetch inputs of the transaction to sign
        for txinput in tx.inputs:
            if ('is_coinbase' in txinput and txinput['is_coinbase']):
                self.give_error("Coinbase not supported")     # should never happen
            inputs.append([ self.transactions[txinput['prevout_hash']].raw,
                             txinput['prevout_n'] ])
            address = txinput['address']
            inputsPaths.append(self.address_id(address))
            pubKeys.append(self.get_public_keys(address))

        # Recognize outputs - only one output and one change is authorized
        if len(tx.outputs) > 2: # should never happen
            self.give_error("Transaction with more than 2 outputs not supported")
        for type, address, amount in tx.outputs:
            assert type == 'address'
            if self.is_change(address):
                changePath = self.address_id(address)
                changeAmount = amount
            else:
                if output <> None: # should never happen
                    self.give_error("Multiple outputs with no change not supported")
                output = address
                if not self.canAlternateCoinVersions:
                    v, h = bc_address_to_hash_160(address)
                    if v == 48:
                        output = hash_160_to_bc_address(h, 0)
                outputAmount = amount

        self.get_client() # prompt for the PIN before displaying the dialog if necessary
        if not self.check_proper_device():
            self.give_error('Wrong device or password')

        self.plugin.handler.show_message("Signing Transaction ...")
        try:
            # Get trusted inputs from the original transactions
            for utxo in inputs:
                txtmp = bitcoinTransaction(bytearray(utxo[0].decode('hex')))
                trustedInputs.append(self.get_client().getTrustedInput(txtmp, utxo[1]))
                # TODO : Support P2SH later
                redeemScripts.append(txtmp.outputs[utxo[1]].script)
            # Sign all inputs
            firstTransaction = True
            inputIndex = 0
            while inputIndex < len(inputs):
                self.get_client().startUntrustedTransaction(firstTransaction, inputIndex,
                trustedInputs, redeemScripts[inputIndex])
                outputData = self.get_client().finalizeInput(output, format_satoshis_plain(outputAmount),
                format_satoshis_plain(self.get_tx_fee(tx)), changePath, bytearray(rawTx.decode('hex')))
                if firstTransaction:
                    transactionOutput = outputData['outputData']
                if outputData['confirmationNeeded']:                    
                    # TODO : handle different confirmation types. For the time being only supports keyboard 2FA
                    self.plugin.handler.stop()
                    if 'keycardData' in outputData:
                        pin2 = ""
                        for keycardIndex in range(len(outputData['keycardData'])):
                            msg = "Do not enter your device PIN here !\r\n\r\n" + \
                                "Your BTChip wants to talk to you and tell you a unique second factor code.\r\n" + \
                                "For this to work, please match the character between stars of the output address using your security card\r\n\r\n" + \
                                "Output address : "
                            for index in range(len(output)):
                                if index == outputData['keycardData'][keycardIndex]:
                                    msg = msg + "*" + output[index] + "*"
                                else:
                                    msg = msg + output[index]
                            msg = msg + "\r\n"
                            confirmed, p, pin = self.password_dialog(msg)
                            if not confirmed:
                                raise Exception('Aborted by user')
                            try:
                                pin2 = pin2 + chr(int(pin[0], 16))
                            except:
                                raise Exception('Invalid PIN character')
                        pin = pin2
                    else:
                        use2FA = True
                        confirmed, p, pin = self.password_dialog()
                        if not confirmed:
                            raise Exception('Aborted by user')
                        pin = pin.encode()
                        self.client.bad = True
                        self.device_checked = False
                        self.get_client(True)
                    self.plugin.handler.show_message("Signing ...")
                else:
                    # Sign input with the provided PIN
                    inputSignature = self.get_client().untrustedHashSign(inputsPaths[inputIndex],
                    pin)
                    inputSignature[0] = 0x30 # force for 1.4.9+
                    signatures.append(inputSignature)
                    inputIndex = inputIndex + 1
                firstTransaction = False
        except Exception, e:
            self.give_error(e, True)
        finally:
            self.plugin.handler.stop()

        # Reformat transaction
        inputIndex = 0
        while inputIndex < len(inputs):
            # TODO : Support P2SH later
            inputScript = get_regular_input_script(signatures[inputIndex], pubKeys[inputIndex][0].decode('hex'))
            preparedTrustedInputs.append([ trustedInputs[inputIndex]['value'], inputScript ])
            inputIndex = inputIndex + 1
        updatedTransaction = format_transaction(transactionOutput, preparedTrustedInputs)
        updatedTransaction = hexlify(updatedTransaction)
        tx.update(updatedTransaction)
        self.client.bad = use2FA
        self.signing = False

    def check_proper_device(self):
        pubKey = DecodeBase58Check(self.master_public_keys["x/0'"])[45:]
        if not self.device_checked:
            self.plugin.handler.show_message("Checking device")
            try:
                nodeData = self.get_client().getWalletPublicKey("44'/2'/0'")
            except Exception, e:
                self.give_error(e, True)
            finally:
                self.plugin.handler.stop()
            pubKeyDevice = compress_public_key(nodeData['publicKey'])
            self.device_checked = True
            if pubKey != pubKeyDevice:
                self.proper_device = False
            else:
                self.proper_device = True

        return self.proper_device

    def password_dialog(self, msg=None):
        if not msg:
            msg = _("Do not enter your device PIN here !\r\n\r\n" \
                    "Your BTChip wants to talk to you and tell you a unique second factor code.\r\n" \
                    "For this to work, please open a text editor (on a different computer / device if you believe this computer is compromised) and put your cursor into it, unplug your BTChip and plug it back in.\r\n" \
                    "It should show itself to your computer as a keyboard and output the second factor along with a summary of the transaction it is signing into the text-editor.\r\n\r\n" \
                    "Check that summary and then enter the second factor code here.\r\n" \
                    "Before clicking OK, re-plug the device once more (unplug it and plug it again if you read the second factor code on the same computer)")
        response = self.plugin.handler.prompt_auth(msg)
        if response is None:
            return False, None, None
        return True, response, response

class BTChipQTHandler:

    def __init__(self, win):
        self.win = win
        self.win.connect(win, SIGNAL('btchip_done'), self.dialog_stop)
        self.win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        self.win.connect(win, SIGNAL('auth_dialog'), self.auth_dialog)
        self.done = threading.Event()

    def stop(self):
        self.win.emit(SIGNAL('btchip_done'))

    def show_message(self, msg):
        self.message = msg
        self.win.emit(SIGNAL('message_dialog'))

    def prompt_auth(self, msg):
        self.done.clear()
        self.message = msg
        self.win.emit(SIGNAL('auth_dialog'))
        self.done.wait()
        return self.response

    def auth_dialog(self):
        response = QInputDialog.getText(None, "BTChip Authentication", self.message, QLineEdit.Password)        
        if not response[1]:
            self.response = None
        else:
            self.response = str(response[0])
        self.done.set()

    def message_dialog(self):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('BTChip')
        self.d.setWindowFlags(self.d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        l = QLabel(self.message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.d.show()

    def dialog_stop(self):
        if self.d is not None:
            self.d.hide()
            self.d = None

class BTChipCmdLineHandler:

    def stop(self):
        pass

    def show_message(self, msg):
        print_msg(msg)

    def prompt_auth(self, msg):
        import getpass        
        print_msg(msg)
        response = getpass.getpass('')
        if len(response) == 0:
            return None
        return response
