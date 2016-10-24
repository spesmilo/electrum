from binascii import hexlify
from struct import pack, unpack
import hashlib
import time
import sys
import traceback

import electrum
from electrum.bitcoin import EncodeBase58Check, DecodeBase58Check, TYPE_ADDRESS, int_to_hex, var_int
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.keystore import Hardware_KeyStore, parse_xpubkey
from ..hw_wallet import HW_PluginBase
from electrum.util import format_satoshis_plain, print_error


try:
    import hid
    from btchip.btchipComm import HIDDongleHIDAPI, DongleWait
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script, get_p2sh_input_script
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipPersoWizard import StartBTChipPersoDialog
    from btchip.btchipFirmwareWizard import checkFirmware, updateFirmware
    from btchip.btchipException import BTChipException
    BTCHIP = True
    BTCHIP_DEBUG = False
except ImportError:
    BTCHIP = False

class Ledger_Client():
    def __init__(self, hidDevice):
        self.dongleObject = btchip(hidDevice)
        self.preflightDone = False

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

    def i4b(self, x):
        return pack('>I', x)        

    def get_xpub(self, bip32_path):
        self.checkDevice()
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        #self.get_client() # prompt for the PIN before displaying the dialog if necessary
        #self.handler.show_message("Computing master public key")
        try:
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
            if len(lastChild) == 1:
                childnum = int(lastChild[0])
            else:
                childnum = 0x80000000 | int(lastChild[0])
            xpub = "0488B21E".decode('hex') + chr(depth) + self.i4b(fingerprint) + self.i4b(childnum) + str(nodeData['chainCode']) + str(publicKey)
        except Exception, e:
            #self.give_error(e, True)
            return None
        finally:
            #self.handler.clear_dialog()
            pass

        return EncodeBase58Check(xpub)

    def has_detached_pin_support(self, client):
        try:
            client.getVerifyPinRemainingAttempts()
            return True
        except BTChipException, e:
            if e.sw == 0x6d00:
                return False
            raise e

    def is_pin_validated(self, client):
        try:
            # Invalid SET OPERATION MODE to verify the PIN status
            client.dongle.exchange(bytearray([0xe0, 0x26, 0x00, 0x00, 0x01, 0xAB]))
        except BTChipException, e:
            if (e.sw == 0x6982):
                return False
            if (e.sw == 0x6A80):
                return True
            raise e

    def perform_hw1_preflight(self):
        try:
            firmware = self.dongleObject.getFirmwareVersion()['version'].split(".")
            if not checkFirmware(firmware):
                self.dongleObject.dongle.close()
                raise Exception("HW1 firmware version too old. Please update at https://www.ledgerwallet.com")
            try:
                self.dongleObject.getOperationMode()
            except BTChipException, e:
                if (e.sw == 0x6985):
                    self.dongleObject.dongle.close()
                    dialog = StartBTChipPersoDialog()
                    dialog.exec_()
                    # Acquire the new client on the next run
                else:
                    raise e
            if self.has_detached_pin_support(self.dongleObject) and not self.is_pin_validated(self.dongleObject) and (self.handler <> None):
                remaining_attempts = self.dongleObject.getVerifyPinRemainingAttempts()
                if remaining_attempts <> 1:
                    msg = "Enter your Ledger PIN - remaining attempts : " + str(remaining_attempts)
                else:
                    msg = "Enter your Ledger PIN - WARNING : LAST ATTEMPT. If the PIN is not correct, the dongle will be wiped."
                confirmed, p, pin = self.password_dialog(msg)
                if not confirmed:
                    raise Exception('Aborted by user - please unplug the dongle and plug it again before retrying')
                pin = pin.encode()
                self.dongleObject.verifyPin(pin)
        except BTChipException, e:
            if (e.sw == 0x6faa):
                raise Exception("Dongle is temporarily locked - please unplug it and replug it again")
            if ((e.sw & 0xFFF0) == 0x63c0):
                raise Exception("Invalid PIN - please unplug the dongle and plug it again before retrying")
            raise e

    def checkDevice(self):
        if not self.preflightDone:
            try:
                self.perform_hw1_preflight()
            except BTChipException as e:
                if (e.sw == 0x6d00):
                    raise BaseException("Device not in Bitcoin mode")
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

    def get_derivation(self):
        return self.derivation        

    def get_client(self):
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

    def address_id_stripped(self, address):
        # Strip the leading "m/"
        change, index = self.get_address_index(address)
        derivation = self.derivation
        address_path = "%s/%d/%d"%(derivation, change, index)
        return address_path[2:]

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Encryption and decryption are currently not supported for %s') % self.device)

    def sign_message(self, sequence, message, password):
        self.signing = True
        # prompt for the PIN before displaying the dialog if necessary
        client = self.get_client()
        address_path = self.get_derivation()[2:] + "/%d/%d"%sequence
        self.handler.show_message("Signing message ...")
        try:
            info = self.get_client().signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                # TODO : handle different confirmation types. For the time being only supports keyboard 2FA
                confirmed, p, pin = self.password_dialog()
                if not confirmed:
                    raise Exception('Aborted by user')
                pin = pin.encode()
                #self.plugin.get_client(self, True, True)
            signature = self.get_client().signMessageSign(pin)
        except BTChipException, e:
            if e.sw == 0x6a80:
                self.give_error("Unfortunately, this message cannot be signed by the Ledger wallet. Only alphanumerical messages shorter than 140 characters are supported. Please remove any extra characters (tab, carriage return) and retry.")
            else:
                self.give_error(e, True)
        except Exception, e:
            self.give_error(e, True)
        finally:
            self.handler.clear_dialog()
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
        return chr(27 + 4 + (signature[0] & 0x01)) + r + s

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        client = self.get_client()
        self.signing = True
        inputs = []
        inputsPaths = []
        pubKeys = []
        chipInputs = []
        redeemScripts = []
        signatures = []
        preparedTrustedInputs = []
        changePath = ""
        changeAmount = None
        output = None
        outputAmount = None
        p2shTransaction = False
	reorganize = False
        pin = ""
        self.get_client() # prompt for the PIN before displaying the dialog if necessary

        # Fetch inputs of the transaction to sign
        derivations = self.get_tx_derivations(tx)
        for txin in tx.inputs():
            if txin.get('is_coinbase'):
                self.give_error("Coinbase not supported")     # should never happen

            if len(txin['pubkeys']) > 1:
                p2shTransaction = True

            for i, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_pubkey in derivations:
                    signingPos = i
                    s = derivations.get(x_pubkey)
                    hwAddress = "%s/%d/%d" % (self.get_derivation()[2:], s[0], s[1])
                    break
            else:
                self.give_error("No matching x_key for sign_transaction") # should never happen

            inputs.append([txin['prev_tx'].raw, txin['prevout_n'], txin.get('redeemScript'), txin['prevout_hash'], signingPos ])
            inputsPaths.append(hwAddress)
            pubKeys.append(txin['pubkeys'])

        # Sanity check
        if p2shTransaction:
            for txinput in tx.inputs():
                if len(txinput['pubkeys']) < 2:
                    self.give_error("P2SH / regular input mixed in same transaction not supported") # should never happen

        txOutput = var_int(len(tx.outputs()))
        for txout in tx.outputs():
            output_type, addr, amount = txout
            txOutput += int_to_hex(amount, 8)
            script = tx.pay_script(output_type, addr)
            txOutput += var_int(len(script)/2)
            txOutput += script
        txOutput = txOutput.decode('hex')

        # Recognize outputs - only one output and one change is authorized
        if not p2shTransaction:
            if len(tx.outputs()) > 2: # should never happen
                self.give_error("Transaction with more than 2 outputs not supported")
            for _type, address, amount in tx.outputs():
                assert _type == TYPE_ADDRESS
                info = tx.output_info.get(address)
                if info is not None:
                    index, xpubs, m = info
                    changePath = self.get_derivation()[2:] + "/%d/%d"%index
                    changeAmount = amount
                else:
                    output = address
                    outputAmount = amount

        self.handler.show_message(_("Confirm Transaction on your Ledger device..."))
        try:
            # Get trusted inputs from the original transactions
            for utxo in inputs:                
                if not p2shTransaction:
                    txtmp = bitcoinTransaction(bytearray(utxo[0].decode('hex')))             
                    chipInputs.append(self.get_client().getTrustedInput(txtmp, utxo[1]))
                    redeemScripts.append(txtmp.outputs[utxo[1]].script)                    
                else:
                    tmp = utxo[3].decode('hex')[::-1].encode('hex')
                    tmp += int_to_hex(utxo[1], 4)
                    chipInputs.append({'value' : tmp.decode('hex')})
                    redeemScripts.append(bytearray(utxo[2].decode('hex')))

            # Sign all inputs
            firstTransaction = True
            inputIndex = 0
            rawTx = tx.serialize()
            while inputIndex < len(inputs):
                self.get_client().startUntrustedTransaction(firstTransaction, inputIndex,
                                                            chipInputs, redeemScripts[inputIndex])
                if not p2shTransaction:
                    outputData = self.get_client().finalizeInput(output, format_satoshis_plain(outputAmount),
                        format_satoshis_plain(tx.get_fee()), changePath, bytearray(rawTx.decode('hex')))
                    reorganize = True
                else:
                    outputData = self.get_client().finalizeInputFull(txOutput)
                    outputData['outputData'] = txOutput

                if firstTransaction:
                    transactionOutput = outputData['outputData']
                if outputData['confirmationNeeded']:
                    # TODO : handle different confirmation types. For the time being only supports keyboard 2FA
                    self.handler.clear_dialog()
                    if 'keycardData' in outputData:
                        pin2 = ""
                        for keycardIndex in range(len(outputData['keycardData'])):
                            msg = "Do not enter your device PIN here !\r\n\r\n" + \
                                "Your Ledger Wallet wants to talk to you and tell you a unique second factor code.\r\n" + \
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
                        confirmed, p, pin = self.password_dialog()
                        if not confirmed:
                            raise Exception('Aborted by user')
                        pin = pin.encode()
                        #self.plugin.get_client(self, True, True)
                    self.handler.show_message("Signing ...")
                else:
                    # Sign input with the provided PIN
                    inputSignature = self.get_client().untrustedHashSign(inputsPaths[inputIndex],
                    pin)
                    inputSignature[0] = 0x30 # force for 1.4.9+
                    signatures.append(inputSignature)
                    inputIndex = inputIndex + 1
                firstTransaction = False
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.give_error(e, True)
        finally:
            self.handler.clear_dialog()

        # Reformat transaction
        inputIndex = 0
        while inputIndex < len(inputs):
            if p2shTransaction:
                signaturesPack = [signatures[inputIndex]] * len(pubKeys[inputIndex])
                inputScript = get_p2sh_input_script(redeemScripts[inputIndex], signaturesPack)
                preparedTrustedInputs.append([ ("\x00" * 4) + chipInputs[inputIndex]['value'], inputScript ])                
            else:
                inputScript = get_regular_input_script(signatures[inputIndex], pubKeys[inputIndex][0].decode('hex'))
                preparedTrustedInputs.append([ chipInputs[inputIndex]['value'], inputScript ])
            inputIndex = inputIndex + 1
        updatedTransaction = format_transaction(transactionOutput, preparedTrustedInputs)
        updatedTransaction = hexlify(updatedTransaction)

        if reorganize:
           tx.update(updatedTransaction)
        else:
           tx.update_signatures(updatedTransaction)
        self.signing = False

    def password_dialog(self, msg=None):
        if not msg:
            msg = _("Do not enter your device PIN here !\r\n\r\n" \
                    "Your Ledger Wallet wants to talk to you and tell you a unique second factor code.\r\n" \
                    "For this to work, please open a text editor " \
                    "(on a different computer / device if you believe this computer is compromised) " \
                    "and put your cursor into it, unplug your Ledger Wallet and plug it back in.\r\n" \
                    "It should show itself to your computer as a keyboard " \
                    "and output the second factor along with a summary of " \
                    "the transaction being signed into the text-editor.\r\n\r\n" \
                    "Check that summary and then enter the second factor code here.\r\n" \
                    "Before clicking OK, re-plug the device once more (unplug it and plug it again if you read the second factor code on the same computer)")
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response


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
                   (0x2c97, 0x0001)  # Nano-S
                 ]

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        if self.libraries_available:
            self.device_manager().register_devices(self.DEVICE_IDS)

    def btchip_is_connected(self, keystore):
        try:
            self.get_client(keystore).getFirmwareVersion()
        except Exception as e:
            return False
        return True

    def get_btchip_device(self, device):
        ledger = False
        if (device.product_key[0] == 0x2581 and device.product_key[1] == 0x3b7c) or (device.product_key[0] == 0x2581 and device.product_key[1] == 0x4b7c) or (device.product_key[0] == 0x2c97):
           ledger = True        
        dev = hid.device()
        dev.open_path(device.path)
        dev.set_nonblocking(True)
        return HIDDongleHIDAPI(dev, ledger, BTCHIP_DEBUG)
	
    def create_client(self, device, handler):
        self.handler = handler

        client = self.get_btchip_device(device)
        if client <> None:
            client = Ledger_Client(client)
        return client

    def setup_device(self, device_info, wizard):        
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        #client.handler = wizard
        client.handler = self.create_handler(wizard)
        #client.get_xpub('m')
        client.get_xpub("m/44'/0'") # TODO replace by direct derivation once Nano S > 1.1

    def get_xpub(self, device_id, derivation, wizard):
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        #client.handler = wizard
        client.handler = self.create_handler(wizard)
        client.checkDevice()
        xpub = client.get_xpub(derivation)
        return xpub

    def get_client(self, keystore, force_pair=True):
        # All client interaction should not be in the main GUI thread
        #assert self.main_thread != threading.current_thread()
        devmgr = self.device_manager()
        handler = keystore.handler
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)        
        # returns the client for a given keystore. can use xpub
        #if client:
        #    client.used()
        if client <> None:
            client.checkDevice()
            client = client.dongleObject            
        return client
