from binascii import hexlify
from struct import unpack
import hashlib
import time

import electrum
from electrum.bitcoin import EncodeBase58Check, DecodeBase58Check, TYPE_ADDRESS
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from ..hw_wallet import BIP44_HW_Wallet
from ..hw_wallet import HW_PluginBase
from electrum.util import format_satoshis_plain, print_error


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


class BTChipWallet(BIP44_HW_Wallet):
    wallet_type = 'btchip'
    device = 'Ledger'

    def __init__(self, storage):
        BIP44_HW_Wallet.__init__(self, storage)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.handler = None
        self.force_watching_only = False
        self.device_checked = False
        self.signing = False

    def give_error(self, message, clear_client = False):
        print_error(message)
        if not self.signing:
            self.handler.show_error(message)
        else:
            self.signing = False
        if clear_client:
            self.plugin.client = None
            self.device_checked = False
        raise Exception(message)

    def address_id(self, address):
        # Strip the leading "m/"
        return BIP44_HW_Wallet.address_id(self, address)[2:]

    def get_public_key(self, bip32_path):
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        self.get_client() # prompt for the PIN before displaying the dialog if necessary
        self.handler.show_message("Computing master public key")
        try:
            splitPath = bip32_path.split('/')
            if splitPath[0] == 'm':
                splitPath = splitPath[1:]
                bip32_path = bip32_path[2:]
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
            self.handler.clear_dialog()

        return EncodeBase58Check(xpub)

    def decrypt_message(self, pubkey, message, password):
        self.give_error("Not supported")

    def sign_message(self, address, message, password):
        use2FA = False
        self.signing = True
        # prompt for the PIN before displaying the dialog if necessary
        client = self.get_client()
        if not self.check_proper_device():
            self.give_error('Wrong device or password')
        address_path = self.address_id(address)
        self.handler.show_message("Signing message ...")
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
                client.bad = True
                self.device_checked = False
                self.plugin.get_client(self, True, True)
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
        client.bad = use2FA
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
        for txinput in tx.inputs():
            if ('is_coinbase' in txinput and txinput['is_coinbase']):
                self.give_error("Coinbase not supported")     # should never happen
            inputs.append([ self.transactions[txinput['prevout_hash']].raw,
                             txinput['prevout_n'] ])
            address = txinput['address']
            inputsPaths.append(self.address_id(address))
            pubKeys.append(self.get_public_keys(address))

        # Recognize outputs - only one output and one change is authorized
        if len(tx.outputs()) > 2: # should never happen
            self.give_error("Transaction with more than 2 outputs not supported")
        for type, address, amount in tx.outputs():
            assert type == TYPE_ADDRESS
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

        self.handler.show_message("Signing Transaction ...")
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
                        use2FA = True
                        confirmed, p, pin = self.password_dialog()
                        if not confirmed:
                            raise Exception('Aborted by user')
                        pin = pin.encode()
                        client.bad = True
                        self.device_checked = False
                        self.plugin.get_client(self, True, True)
                    self.handler.show_message("Signing ...")
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
            self.handler.clear_dialog()

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
        client.bad = use2FA
        self.signing = False

    def check_proper_device(self):
        pubKey = DecodeBase58Check(self.master_public_keys["x/0'"])[45:]
        if not self.device_checked:
            self.handler.show_message("Checking device")
            try:
                nodeData = self.get_client().getWalletPublicKey("44'/0'/0'")
            except Exception, e:
                self.give_error(e, True)
            finally:
                self.handler.clear_dialog()
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
    wallet_class = BTChipWallet

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        # FIXME shouldn't be a plugin member.  Then this constructor can go.
        self.client = None

    def btchip_is_connected(self, wallet):
        try:
            wallet.get_client().getFirmwareVersion()
        except:
            return False
        return True

    def get_client(self, wallet, force_pair=True, noPin=False):
        aborted = False
        client = self.client
        if not client or client.bad:
            try:
                d = getDongle(BTCHIP_DEBUG)
                client = btchip(d)
                firmware = client.getFirmwareVersion()['version'].split(".")
                if not checkFirmware(firmware):
                    d.close()
                    try:
                        updateFirmware()
                    except Exception, e:
                        aborted = True
                        raise e
                    d = getDongle(BTCHIP_DEBUG)
                    client = btchip(d)
                try:
                    client.getOperationMode()
                except BTChipException, e:
                    if (e.sw == 0x6985):
                        d.close()
                        dialog = StartBTChipPersoDialog()
                        dialog.exec_()
                        # Then fetch the reference again  as it was invalidated
                        d = getDongle(BTCHIP_DEBUG)
                        client = btchip(d)
                    else:
                        raise e
                if not noPin:
                    # Immediately prompts for the PIN
                    remaining_attempts = client.getVerifyPinRemainingAttempts()
                    if remaining_attempts <> 1:
                        msg = "Enter your Ledger PIN - remaining attempts : " + str(remaining_attempts)
                    else:
                        msg = "Enter your Ledger PIN - WARNING : LAST ATTEMPT. If the PIN is not correct, the dongle will be wiped."
                    confirmed, p, pin = wallet.password_dialog(msg)
                    if not confirmed:
                        aborted = True
                        raise Exception('Aborted by user - please unplug the dongle and plug it again before retrying')
                    pin = pin.encode()
                    client.verifyPin(pin)

            except BTChipException, e:
                try:
                    client.dongle.close()
                except:
                    pass
                client = None
                if (e.sw == 0x6faa):
                    raise Exception("Dongle is temporarily locked - please unplug it and replug it again")
                if ((e.sw & 0xFFF0) == 0x63c0):
                    raise Exception("Invalid PIN - please unplug the dongle and plug it again before retrying")
                raise e
            except Exception, e:
                try:
                    client.dongle.close()
                except:
                    pass
                client = None
                if not aborted:
                    raise Exception("Could not connect to your Ledger wallet. Please verify access permissions, PIN, or unplug the dongle and plug it again")
                else:
                    raise e
            client.bad = False
            wallet.device_checked = False
            wallet.proper_device = False
            self.client = client

        return self.client
