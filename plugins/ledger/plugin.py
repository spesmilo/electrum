import base64
import re
import threading
import time

from binascii import unhexlify
from struct import pack
from functools import partial

from electrum.account import BIP32_Account
from electrum.bitcoin import (bc_address_to_hash_160, xpub_from_pubkey,
                              public_key_to_bc_address, EncodeBase58Check, TYPE_ADDRESS)
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import (deserialize, is_extended_pubkey,
                                  Transaction, x_to_xpub)
from electrum.wallet import BIP32_HD_Wallet, BIP44_Wallet
from electrum.util import ThreadJob, format_satoshis_plain
from electrum.plugins import DeviceMgr

import hid
import hashlib
from binascii import hexlify
from struct import unpack
from btchip.btchip import btchip
from btchip.btchipComm import HIDDongleHIDAPI
from btchip.btchipException import BTChipException
from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script
from btchip.bitcoinTransaction import bitcoinTransaction

class DeviceDisconnectedError(Exception):
    pass

class DeviceNotInitializedError(Exception):
    pass

class NotImplementedError(Exception):
    pass

class DeviceLockedError(Exception):
    pass

class LedgerCompatibleWallet(BIP44_Wallet):
    # Extend BIP44 Wallet as required by hardware implementation.
    # Derived classes must set:
    #   - device
    #   - DEVICE_IDS
    #   - wallet_type

    restore_wallet_class = BIP44_Wallet

    def __init__(self, storage):
        BIP44_Wallet.__init__(self, storage)
        # After timeout seconds we clear the device session
        self.session_timeout = storage.get('session_timeout', 180)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.handler = None
        self.force_watching_only = True
        self.pin_presented = False

    def set_session_timeout(self, seconds):
        self.print_error("setting session timeout to %d seconds" % seconds)
        self.session_timeout = seconds
        self.storage.put('session_timeout', seconds)

    def unpaired(self):
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        self.print_error("unpaired")
        self.force_watching_only = True
        self.handler.watching_only_changed()

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        self.print_error("paired")
        self.force_watching_only = False
        self.handler.watching_only_changed()

    def timeout(self):
        '''Informs the wallet it timed out.  Note this is called from
        the Plugins thread.'''
        #self.print_error("timed out")

    def get_action(self):
        pass

    def can_create_accounts(self):
        return True

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is watching-only if its associated hardware device is unpaired.'''
        assert not self.has_seed()
        return self.force_watching_only

    def address_id(self, address):
        # Strip the leading "m/"
        return BIP44_Wallet.address_id(self, address)[2:]

    def can_change_password(self):
        return False

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def first_address(self):
        '''Used to check a hardware wallet matches a software wallet'''
        account = self.accounts.get('0')
        derivation = self.address_derivation('0', 0, 0)
        return (account.first_address()[0] if account else None, derivation)

    def derive_xkeys(self, root, derivation, password):
        if self.master_public_keys.get(root):
            return BIP44_wallet.derive_xkeys(self, root, derivation, password)

        # When creating a wallet we need to ask the device for the
        # master public key
        xpub = self.get_public_key(derivation)
        return xpub, None

    def get_public_key(self, bip32_path):
        # S-L-O-W - we don't handle the fingerprint directly, so compute it manually from the previous node
        # This only happens once so it's bearable
        client = self.get_client() # prompt for the PIN before displaying the dialog if necessary
        self.handler.show_message("Computing master public key")        
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
        self.handler.finished()
        return EncodeBase58Check(xpub)

    def i4b(self, x):
        return pack('>I', x)

    def decrypt_message(self, pubkey, message, password):
        raise NotImplementedError()

    def sign_transaction(self, tx, password):
        if tx.is_complete() or self.is_watching_only():
            return
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
                self.handler.show_error("Coinbase not supported")     # should never happen
		raise NotImplementedError("Coinbase not supported")
            inputs.append([ self.transactions[txinput['prevout_hash']].raw,
                             txinput['prevout_n'] ])
            address = txinput['address']
            inputsPaths.append(self.address_id(address))
            pubKeys.append(self.get_public_keys(address))

        # Recognize outputs - only one output and one change is authorized
        if len(tx.outputs()) > 2: # should never happen
            msg = "Transaction with more than 2 outputs not supported"
            self.handler.show_error(msg)
            raise NotImplementedError(msg)
        for type, address, amount in tx.outputs():
            assert type == TYPE_ADDRESS 
            if self.is_change(address):
                changePath = self.address_id(address)
                changeAmount = amount
            else:
                if output <> None: # should never happen
                    msg = "Multiple outputs with no change not supported"
                    self.handler.show_error(msg)
                    raise NotImplementedError(msg)
                output = address
                outputAmount = amount

        self.get_client() # prompt for the PIN before displaying the dialog if necessary
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
                    self.handler.finished()
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
                            confirmed, p, pin = self.plugin.password_dialog(self.handler, msg)
                            if not confirmed:
                                raise Exception('Aborted by user')
                            try:
                                pin2 = pin2 + chr(int(pin[0], 16))
                            except:
                                raise Exception('Invalid PIN character')
                        pin = pin2
                    else:
                        use2FA = True
                        confirmed, p, pin = self.plugin.password_dialog(self.handler)
                        if not confirmed:
                            raise Exception('Aborted by user')
                        pin = pin.encode()
                        self.get_client(True)
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
            raise e

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


    def sign_message(self, address, message, password):
 	self.get_client() # prompt for the PIN before displaying the dialog if necessary
        address_path = self.address_id(address)
        self.handler.show_message("Signing message ...")
        try:
            info = self.get_client().signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                # TODO : handle different confirmation types. For the time being only supports keyboard 2FA
                use2FA = True
                confirmed, p, pin = self.plugin.password_dialog(self.handler)
                if not confirmed:
                    raise Exception('Aborted by user')
                pin = pin.encode()
                self.get_client(True)
            signature = self.get_client().signMessageSign(pin)
        except BTChipException, e:
            if e.sw == 0x6a80:
                self.handler.show_error("Unfortunately, this message cannot be signed by the Ledger wallet. Only alphanumerical messages shorter than 140 characters are supported. Please remove any extra characters (tab, carriage return) and retry.")
            else:
		raise e
        except Exception, e:
	    raise e

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

class LedgerCompatiblePlugin(BasePlugin, ThreadJob):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    MAX_LABEL_LEN = 32
    DEVICE_IDS = [ (0x2581, 0x3b7c) ]
    DEBUG = True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.main_thread = threading.current_thread()
        self.device = self.wallet_class.device
        self.wallet_class.plugin = self
        self.prevent_timeout = time.time() + 3600 * 24 * 365
        if self.libraries_available:
            self.device_manager().register_devices(
                self.DEVICE_IDS)

    def is_enabled(self):
        return self.libraries_available

    def device_manager(self):
        return self.parent.device_manager

    def thread_jobs(self):
        # Thread job to handle device timeouts
        return [self] if self.libraries_available else []

    def run(self):
        '''Handle device timeouts.  Runs in the context of the Plugins
        thread.'''
        now = time.time()
        for wallet in self.device_manager().paired_wallets():
            if (isinstance(wallet, self.wallet_class)
                    and hasattr(wallet, 'last_operation')
                    and now > wallet.last_operation + wallet.session_timeout):
                client = self.get_client(wallet, force_pair=False)
                if client:
                    wallet.last_operation = self.prevent_timeout
                    wallet.timeout()

    def create_client(self, device, handler):
        try:
            dev = hid.device()
            dev.open_path(device.path)
            dev.set_nonblocking(True)            
            transport = HIDDongleHIDAPI(dev, True, self.DEBUG)        
        except BaseException as e:
            # We were probably just disconnected; never mind
            self.print_error("cannot connect at", device.path, str(e))            
            return None
        self.print_error("connected to device at", device.path)
        return self.client_class(transport, handler, self, device.path)

    def get_client(self, wallet, force_pair=True, no_pin=False):
        # All client interaction should not be in the main GUI thread
        assert self.main_thread != threading.current_thread()

        devmgr = self.device_manager()
        client = devmgr.client_for_wallet(self, wallet, force_pair)

        # Try a ping for device sanity
        if client:
            self.print_error("set last_operation")
            wallet.last_operation = time.time()
            try:
                client.getOperationMode()
            except BaseException as e:
                self.print_error("ping failed", str(e))
                # Remove it from the manager's cache
                devmgr.close_client(client)
                client = None

        if force_pair:
            assert wallet.handler
            if not client:
                msg = (_('Could not connect to your %s.  Verify the '
                         'cable is connected and that no other app is '
                         'using it.\nContinuing in watching-only mode '
                         'until the device is re-connected.') % self.device)
                wallet.handler.show_error(msg)
                raise DeviceDisconnectedError(msg)

        if not no_pin and not wallet.pin_presented:
            # Immediately prompts for the PIN
            remaining_attempts = client.getVerifyPinRemainingAttempts()
            if remaining_attempts <> 1:
                msg = "Enter your Ledger PIN - remaining attempts : " + str(remaining_attempts)
            else:
                msg = "Enter your Ledger PIN - WARNING : LAST ATTEMPT. If the PIN is not correct, the dongle will be wiped."
            confirmed, p, pin = self.password_dialog(wallet.handler, msg)
            if not confirmed:
                msg = "Aborted by user - please unplug the dongle and plug it again before retrying"
                wallet.handler.show_error(msg)
                raise DeviceLockedError(msg)
            pin = pin.encode()
            try:
                client.verifyPin(pin)
            except BTChipException, e:
                if ((e.sw & 0xFFF0) == 0x63c0):
                    msg = "Invalid PIN - please unplug the dongle and plug it again before retrying"
                    wallet.handler.show_error(msg)
                    raise DeviceLockedError(msg)
                else:
                    raise e
            wallet.pin_presented = True
        return client

    @hook
    def close_wallet(self, wallet):
        if isinstance(wallet, self.wallet_class):
            self.device_manager().unpair_wallet(wallet)

    def initialize_device(self, wallet):
        msg = "Please initialize the device following instructions on https://www.ledgerwallet.com"
        wallet.handler.show_error(msg)
        raise DeviceNotInitializedError(msg)

    def setup_device(self, wallet, on_done, on_error):
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.  Then create the wallet accounts.'''
        devmgr = self.device_manager()
        device_info = devmgr.select_device(wallet, self)
        devmgr.pair_wallet(wallet, device_info.device.id_)
        if device_info.initialized:
            task = partial(wallet.create_hd_account, None)
        else:
            task = self.initialize_device(wallet)
        wallet.thread.add(task, on_done=on_done, on_error=on_error)

    def on_restore_wallet(self, wallet, wizard):
        assert isinstance(wallet, self.wallet_class)

        msg = _("Enter the seed for your %s wallet:" % self.device)
        seed = wizard.request_seed(msg, is_valid = self.is_valid_seed)

        # Restored wallets are not hardware wallets
        wallet_class = self.wallet_class.restore_wallet_class
        wallet.storage.put('wallet_type', wallet_class.wallet_type)
        wallet = wallet_class(wallet.storage)

        passphrase = wizard.request_passphrase(self.device, restore=True)
        password = wizard.request_password()
        wallet.add_seed(seed, password)
        wallet.add_xprv_from_seed(seed, 'x/', password, passphrase)
        wallet.create_hd_account(password)
        return wallet

    def sign_transaction(self, wallet, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client(wallet)
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(wallet, tx)
        signed_tx = client.sign_tx('Bitcoin', inputs, outputs)[1]
        raw = signed_tx.encode('hex')
        tx.update_signatures(raw)

    def password_dialog(self, handler, msg=None):
        if not msg:
            msg = _("Do not enter your device PIN here !\r\n\r\n" \
                    "Your Ledger Wallet wants to talk to you and tell you a unique second factor code.\r\n" \
                    "For this to work, please open a text editor (on a different computer / device if you believe this computer is compromised) and put your cursor into it, unplug your Ledger Wallet and plug it back in.\r\n" \
                    "It should show itself to your computer as a keyboard and output the second factor along with a summary of the transaction it is signing into the text-editor.\r\n\r\n" \
                    "Check that summary and then enter the second factor code here.\r\n" \
                    "Before clicking OK, re-plug the device once more (unplug it and plug it again if you read the second factor code on the same computer)")
        response = handler.get_auth(msg)
        if response is None:
            return False, None, None
        return True, response, response        


    @staticmethod
    def is_valid_seed(seed):
        return True
