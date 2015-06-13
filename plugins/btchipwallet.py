from PyQt4.Qt import QApplication, QMessageBox, QDialog, QVBoxLayout, QLabel, QThread, SIGNAL
import PyQt4.QtCore as QtCore
from binascii import unhexlify
from binascii import hexlify
from struct import pack,unpack
from sys import stderr
from time import sleep
from base64 import b64encode, b64decode

import electrum
from electrum_gui.qt.password_dialog import make_password_dialog, run_password_dialog
from electrum.account import BIP32_Account
from electrum.bitcoin import EncodeBase58Check, DecodeBase58Check, public_key_to_bc_address, bc_address_to_hash_160
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import deserialize
from electrum.wallet import BIP32_HD_Wallet, BIP32_Wallet

from electrum.util import format_satoshis
import hashlib

try:
    from btchip.btchipComm import getDongle, DongleWait
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipPersoWizard import StartBTChipPersoDialog
    from btchip.btchipFirmwareWizard import checkFirmware, updateFirmware
    from btchip.btchipException import BTChipException
    BTCHIP = True
    BTCHIP_DEBUG = False
except ImportError:
    BTCHIP = False

class Plugin(BasePlugin):

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()
        self.wallet = None

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
    def load_wallet(self, wallet, window):
        self.wallet = wallet
        self.window = window
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
    def send_tx(self, tx):
        tx.error = None
        try:
            self.wallet.sign_transaction(tx, None)
        except Exception as e:
            tx.error = str(e)

class BTChipWallet(BIP32_HD_Wallet):
    wallet_type = 'btchip'
    root_derivation = "m/44'/0'"

    def __init__(self, storage):
        BIP32_HD_Wallet.__init__(self, storage)
        self.transport = None
        self.client = None
        self.mpk = None
        self.device_checked = False
        self.signing = False
        self.force_watching_only = False

    def give_error(self, message, clear_client = False):
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
                d.setWaitImpl(DongleWaitQT(d))
                self.client = btchip(d)
                firmware = self.client.getFirmwareVersion()['version'].split(".")
                if not checkFirmware(firmware):                    
                    d.close()
                    try:
                        updateFirmware()
                    except Exception, e:
                        aborted = True
                        raise e
                    d = getDongle(BTCHIP_DEBUG)
                    d.setWaitImpl(DongleWaitQT(d))
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
                        d.setWaitImpl(DongleWaitQT(d))
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
        return "44'/0'/%s'/%d/%d" % (account_id, change, address_index)

    def create_main_account(self, password):
        self.create_account('Main account', None) #name, empty password

    def derive_xkeys(self, root, derivation, password):
        derivation = derivation.replace(self.root_name,"44'/0'/")
        xpub = self.get_public_key(derivation)
        return xpub, None

    def get_private_key(self, address, password):
        return []

    def get_public_key(self, bip32_path):
        # S-L-O-W - we don't handle the fingerprint directly, so compute it manually from the previous node        
        # This only happens once so it's bearable
        self.get_client() # prompt for the PIN before displaying the dialog if necessary        
        waitDialog.start("Computing master public key")
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
            waitDialog.emit(SIGNAL('dongle_done'))

        return EncodeBase58Check(xpub)

    def get_master_public_key(self):
        try:
            if not self.mpk:
                self.mpk = self.get_public_key("44'/0'")
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
        waitDialog.start("Signing Message ...")
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
            if waitDialog.waiting:
                waitDialog.emit(SIGNAL('dongle_done'))
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
        if tx.error:
            raise BaseException(tx.error)
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
                outputAmount = amount

        self.get_client() # prompt for the PIN before displaying the dialog if necessary
        if not self.check_proper_device():
            self.give_error('Wrong device or password')

        waitDialog.start("Signing Transaction ...")
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
                outputData = self.get_client().finalizeInput(output, format_satoshis(outputAmount), 
                format_satoshis(self.get_tx_fee(tx)), changePath)
                if firstTransaction:
                    transactionOutput = outputData['outputData']
                if outputData['confirmationNeeded']:                
                    use2FA = True
                    # TODO : handle different confirmation types. For the time being only supports keyboard 2FA
                    waitDialog.emit(SIGNAL('dongle_done'))
                    confirmed, p, pin = self.password_dialog()
                    if not confirmed:
                        raise Exception('Aborted by user')
                    pin = pin.encode()
                    self.client.bad = True
                    self.device_checked = False
                    self.get_client(True)
                    waitDialog.start("Signing ...")
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
            if waitDialog.waiting:
                waitDialog.emit(SIGNAL('dongle_done'))

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
            waitDialog.start("Checking device")
            try:
                nodeData = self.get_client().getWalletPublicKey("44'/0'/0'")
            except Exception, e:
                self.give_error(e, True)
            finally:
                waitDialog.emit(SIGNAL('dongle_done'))
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
        d = QDialog()
        d.setModal(1)
        d.setLayout( make_password_dialog(d, None, msg, False) )
        return run_password_dialog(d, None, None)

class DongleWaitingDialog(QThread):
    def __init__(self):
        QThread.__init__(self)
        self.waiting = False

    def start(self, message):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('Please Wait')
        self.d.setWindowFlags(self.d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        l = QLabel(message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.d.show()
        if not self.waiting:
            self.waiting = True
            self.d.connect(waitDialog, SIGNAL('dongle_done'), self.stop)

    def stop(self):
        self.d.hide()
        self.waiting = False

if BTCHIP:
    waitDialog = DongleWaitingDialog()

    # Tickle the UI a bit while waiting
    class DongleWaitQT(DongleWait):
        def __init__(self, dongle):
            self.dongle = dongle

        def waitFirstResponse(self, timeout):
	    return self.dongle.waitFirstResponse(timeout)

