from PyQt4.Qt import QMessageBox, QDialog, QVBoxLayout, QLabel, QThread, SIGNAL, QGridLayout, QInputDialog, QPushButton
import PyQt4.QtCore as QtCore
from binascii import unhexlify
from struct import pack
from sys import stderr
from time import sleep
from base64 import b64encode, b64decode
import unicodedata
import threading

import electrum
from electrum.account import BIP32_Account
from electrum.bitcoin import EncodeBase58Check, public_key_to_bc_address, bc_address_to_hash_160
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook, always_hook, run_hook
from electrum.transaction import deserialize
from electrum.wallet import BIP32_HD_Wallet
from electrum.util import print_error, print_msg
from electrum.wallet import pw_decode, bip32_private_derivation, bip32_root

from electrum_gui.qt.util import *

try:
    from trezorlib.client import types
    from trezorlib.client import proto, BaseClient, ProtocolMixin
    from trezorlib.qt.pinmatrix import PinMatrixWidget
    from trezorlib.transport import ConnectionError
    from trezorlib.transport_hid import HidTransport
    TREZOR = True
except ImportError:
    TREZOR = False

def log(msg):
    stderr.write("%s\n" % msg)
    stderr.flush()

def give_error(message):
    print_error(message)
    raise Exception(message)


class Plugin(BasePlugin):

    def __init__(self, config, name):
        BasePlugin.__init__(self, config, name)
        self._is_available = self._init()
        self._requires_settings = True
        self.wallet = None
        self.handler = None

    def constructor(self, s):
        return TrezorWallet(s)

    def _init(self):
        return TREZOR

    def is_available(self):
        if not self._is_available:
            return False
        if not self.wallet:
            return False
        if self.wallet.storage.get('wallet_type') != 'trezor':
            return False
        return True

    def requires_settings(self):
        return self._requires_settings

    def set_enabled(self, enabled):
        self.wallet.storage.put('use_' + self.name, enabled)

    def is_enabled(self):
        if not self.is_available():
            return False
        if self.wallet.has_seed():
            return False
        return True

    def trezor_is_connected(self):
        try:
            self.wallet.get_client().ping('t')
        except:
            return False
        return True


    @hook
    def close_wallet(self):
        print_error("trezor: clear session")
        if self.wallet and self.wallet.client:
            self.wallet.client.clear_session()
            self.wallet.client.transport.close()
        self.wallet = None

    @hook
    def cmdline_load_wallet(self, wallet):
        self.wallet = wallet
        self.wallet.plugin = self
        if self.handler is None:
            self.handler = TrezorCmdLineHandler()

    @hook
    def load_wallet(self, wallet, window):
        self.print_error("load_wallet")
        self.wallet = wallet
        self.window = window
        self.wallet.plugin = self

        if self.handler is None:
            self.handler = TrezorQtHandler(self.window.app)

        if self.trezor_is_connected():
            if self.wallet.addresses() and not self.wallet.check_proper_device():
                QMessageBox.information(self.window, _('Error'), _("This wallet does not match your Trezor device"), _('OK'))
                self.wallet.force_watching_only = True
        else:
            QMessageBox.information(self.window, _('Error'), _("Trezor device not detected.\nContinuing in watching-only mode."), _('OK'))
            self.wallet.force_watching_only = True

    @hook
    def installwizard_load_wallet(self, wallet, window):
        self.load_wallet(wallet, window)

    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != 'trezor': 
            return
        seed = wizard.enter_seed_dialog("Enter your Trezor seed", None, func=lambda x:True)
        if not seed:
            return
        wallet = TrezorWallet(storage)
        self.wallet = wallet
        passphrase = self.handler.get_passphrase(_("Please enter your Trezor passphrase.") + '\n' + _("Press OK if you do not use one."))
        if passphrase is None:
            return
        password = wizard.password_dialog()
        wallet.add_seed(seed, password)
        wallet.add_cosigner_seed(seed, 'x/', password, passphrase)
        wallet.create_main_account(password)
        # disable trezor plugin
        self.set_enabled(False)
        return wallet

    @hook
    def receive_menu(self, menu, addrs):
        if not self.wallet.is_watching_only() and self.wallet.atleast_version(1, 3) and len(addrs) == 1:
            menu.addAction(_("Show on TREZOR"), lambda: self.wallet.show_address(addrs[0]))

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        get_label = lambda: self.wallet.get_client().features.label
        update_label = lambda: current_label_label.setText("Label: %s" % get_label())

        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel("Trezor Options"),0,0)
        layout.addWidget(QLabel("ID:"),1,0)
        layout.addWidget(QLabel(" %s" % self.wallet.get_client().get_device_id()),1,1)

        def modify_label():
            response = QInputDialog().getText(None, "Set New Trezor Label", "New Trezor Label:  (upon submission confirm on Trezor)")
            if not response[1]:
                return
            new_label = str(response[0])
            self.handler.show_message("Please confirm label change on Trezor")
            status = self.wallet.get_client().apply_settings(label=new_label)
            self.handler.stop()
            update_label()

        current_label_label = QLabel()
        update_label()
        change_label_button = QPushButton("Modify")
        change_label_button.clicked.connect(modify_label)
        layout.addWidget(current_label_label,3,0)
        layout.addWidget(change_label_button,3,1)

        if d.exec_():
            return True
        else:
            return False



class TrezorWallet(BIP32_HD_Wallet):
    wallet_type = 'trezor'
    root_derivation = "m/44'/0'"

    def __init__(self, storage):
        BIP32_HD_Wallet.__init__(self, storage)
        self.transport = None
        self.client = None
        self.mpk = None
        self.device_checked = False
        self.force_watching_only = False

    def get_action(self):
        if not self.accounts:
            return 'create_accounts'

    def can_import(self):
        return False

    def can_sign_xpubkey(self, x_pubkey):
        xpub, sequence = BIP32_Account.parse_xpubkey(x_pubkey)
        return xpub in self.master_public_keys.values()

    def can_export(self):
        return False

    def can_create_accounts(self):
        return True

    def can_change_password(self):
        return False

    def is_watching_only(self):
        return self.force_watching_only

    def get_client(self):
        if not TREZOR:
            give_error('please install github.com/trezor/python-trezor')

        if not self.client or self.client.bad:
            try:
                d = HidTransport.enumerate()[0]
                self.transport = HidTransport(d)
            except:
                give_error('Could not connect to your Trezor. Please verify the cable is connected and that no other app is using it.')
            self.client = QtGuiTrezorClient(self.transport)
            self.client.handler = self.plugin.handler
            self.client.set_tx_api(self)
            #self.client.clear_session()# TODO Doesn't work with firmware 1.1, returns proto.Failure
            self.client.bad = False
            self.device_checked = False
            self.proper_device = False
            if not self.atleast_version(1, 2, 1):
                give_error('Outdated Trezor firmware. Please update the firmware from https://www.mytrezor.com')
        return self.client

    def compare_version(self, major, minor=0, patch=0):
        features = self.get_client().features
        return cmp([features.major_version, features.minor_version, features.patch_version], [major, minor, patch])

    def atleast_version(self, major, minor=0, patch=0):
        return self.compare_version(major, minor, patch) >= 0

    def address_id(self, address):
        account_id, (change, address_index) = self.get_address_index(address)
        return "44'/0'/%s'/%d/%d" % (account_id, change, address_index)

    def create_main_account(self, password):
        self.create_account('Main account', None) #name, empty password

    def mnemonic_to_seed(self, mnemonic, passphrase):
        # trezor uses bip39
        import pbkdf2, hashlib, hmac
        PBKDF2_ROUNDS = 2048
        mnemonic = unicodedata.normalize('NFKD', ' '.join(mnemonic.split()))
        passphrase = unicodedata.normalize('NFKD', passphrase)
        return pbkdf2.PBKDF2(mnemonic, 'mnemonic' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

    def derive_xkeys(self, root, derivation, password):
        x = self.master_private_keys.get(root)
        if x:
            root_xprv = pw_decode(x, password)
            xprv, xpub = bip32_private_derivation(root_xprv, root, derivation)
            return xpub, xprv
        else:
            derivation = derivation.replace(self.root_name,"44'/0'/")
            xpub = self.get_public_key(derivation)
            return xpub, None

    def get_public_key(self, bip32_path):
        address_n = self.get_client().expand_path(bip32_path)
        node = self.get_client().get_public_node(address_n).node
        xpub = "0488B21E".decode('hex') + chr(node.depth) + self.i4b(node.fingerprint) + self.i4b(node.child_num) + node.chain_code + node.public_key
        return EncodeBase58Check(xpub)

    def get_master_public_key(self):
        if not self.mpk:
            self.mpk = self.get_public_key("44'/0'")
        return self.mpk

    def i4b(self, x):
        return pack('>I', x)

    def add_keypairs(self, tx, keypairs, password):
        #do nothing - no priv keys available
        pass

    def decrypt_message(self, pubkey, message, password):
        raise BaseException( _('Decrypt method is not implemented in Trezor') )
        #address = public_key_to_bc_address(pubkey.decode('hex'))
        #address_path = self.address_id(address)
        #address_n = self.get_client().expand_path(address_path)
        #try:
        #    decrypted_msg = self.get_client().decrypt_message(address_n, b64decode(message))
        #except Exception, e:
        #    give_error(e)
        #finally:
        #    twd.stop()
        #return str(decrypted_msg)

    def show_address(self, address):
        if not self.check_proper_device():
            give_error('Wrong device or password')
        try:
            address_path = self.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception, e:
            give_error(e)
        try:
            self.get_client().get_address('Bitcoin', address_n, True)
        except Exception, e:
            give_error(e)
        finally:
            self.plugin.handler.stop()

    def sign_message(self, address, message, password):
        if not self.check_proper_device():
            give_error('Wrong device or password')
        try:
            address_path = self.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception, e:
            give_error(e)
        try:
            msg_sig = self.get_client().sign_message('Bitcoin', address_n, message)
        except Exception, e:
            give_error(e)
        finally:
            self.plugin.handler.stop()
        b64_msg_sig = b64encode(msg_sig.signature)
        return str(b64_msg_sig)

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        if not self.check_proper_device():
            give_error('Wrong device or password')
        client = self.get_client()
        inputs = self.tx_inputs(tx)
        outputs = self.tx_outputs(tx)
        try:
            signed_tx = self.get_client().sign_tx('Bitcoin', inputs, outputs)[1]
        except Exception, e:
            give_error(e)
        finally:
            self.plugin.handler.stop()
        #values = [i['value'] for i in tx.inputs]
        raw = signed_tx.encode('hex')
        tx.update(raw)
        #for i, txinput in enumerate(tx.inputs):
        #    txinput['value'] = values[i]

    def tx_inputs(self, tx):
        inputs = []
        for txinput in tx.inputs:
            txinputtype = types.TxInputType()
            if ('is_coinbase' in txinput and txinput['is_coinbase']):
                prev_hash = "\0"*32
                prev_index = 0xffffffff # signed int -1
            else:
                address = txinput['address']
                try:
                    address_path = self.address_id(address)
                    address_n = self.get_client().expand_path(address_path)
                    txinputtype.address_n.extend(address_n)
                except: pass

                prev_hash = unhexlify(txinput['prevout_hash'])
                prev_index = txinput['prevout_n']

            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if 'scriptSig' in txinput:
                script_sig = txinput['scriptSig'].decode('hex')
                txinputtype.script_sig = script_sig

            if 'sequence' in txinput:
                sequence = txinput['sequence']
                txinputtype.sequence = sequence

            inputs.append(txinputtype)
            #TODO P2SH
        return inputs

    def tx_outputs(self, tx):
        outputs = []

        for type, address, amount in tx.outputs:
            assert type == 'address'
            txoutputtype = types.TxOutputType()
            if self.is_change(address):
                address_path = self.address_id(address)
                address_n = self.get_client().expand_path(address_path)
                txoutputtype.address_n.extend(address_n)
            else:
                txoutputtype.address = address
            txoutputtype.amount = amount
            addrtype, hash_160 = bc_address_to_hash_160(address)
            if addrtype == 0:
                txoutputtype.script_type = types.PAYTOADDRESS
            elif addrtype == 5:
                txoutputtype.script_type = types.PAYTOSCRIPTHASH
            else:
                raise BaseException('addrtype')
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = types.TransactionType()
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']

        inputs = self.tx_inputs(tx)
        t.inputs.extend(inputs)

        for vout in d['outputs']:
            o = t.bin_outputs.add()
            o.amount = vout['value']
            o.script_pubkey = vout['scriptPubKey'].decode('hex')

        return t

    def get_tx(self, tx_hash):
        tx = self.transactions[tx_hash]
        tx.deserialize()
        return self.electrum_tx_to_txtype(tx)

    def check_proper_device(self):
        self.get_client().ping('t')
        if not self.device_checked:
            address = self.addresses(False)[0]
            address_id = self.address_id(address)
            n = self.get_client().expand_path(address_id)
            device_address = self.get_client().get_address('Bitcoin', n)
            self.device_checked = True

            if device_address != address:
                self.proper_device = False
            else:
                self.proper_device = True

        return self.proper_device


class TrezorGuiMixin(object):

    def __init__(self, *args, **kwargs):
        super(TrezorGuiMixin, self).__init__(*args, **kwargs)

    def callback_ButtonRequest(self, msg):
        if msg.code == 3:
            message = "Confirm transaction outputs on Trezor device to continue"
        elif msg.code == 8:
            message = "Confirm transaction fee on Trezor device to continue"
        elif msg.code == 7:
            message = "Confirm message to sign on Trezor device to continue"
        elif msg.code == 10:
            message = "Confirm address on Trezor device to continue"
        else:
            message = "Check Trezor device to continue"
        self.handler.show_message(message)
        return proto.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 1:
            desc = 'current PIN'
        elif msg.type == 2:
            desc = 'new PIN'
        elif msg.type == 3:
            desc = 'new PIN again'
        else:
            desc = 'PIN'
        pin = self.handler.get_pin("Please enter Trezor %s" % desc)
        if not pin:
            return proto.Cancel()
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        msg = _("Please enter your Trezor passphrase.")
        passphrase = self.handler.get_passphrase(msg)
        if passphrase is None:
            return proto.Cancel()
        return proto.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        #TODO
        log("Enter one word of mnemonic: ")
        word = raw_input()
        return proto.WordAck(word=word)


class TrezorCmdLineHandler:

    def get_passphrase(self, msg):
        import getpass
        print_msg(msg)
        return getpass.getpass('')

    def get_pin(self, msg):
        t = { 'a':'7', 'b':'8', 'c':'9', 'd':'4', 'e':'5', 'f':'6', 'g':'1', 'h':'2', 'i':'3'}
        print_msg(msg)
        print_msg("a b c\nd e f\ng h i\n-----")
        o = raw_input()
        return ''.join(map(lambda x: t[x], o))

    def stop(self):
        pass

    def show_message(self, msg):
        print_msg(msg)


class TrezorQtHandler:

    def __init__(self, win):
        self.win = win
        self.win.connect(win, SIGNAL('trezor_done'), self.dialog_stop)
        self.win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        self.win.connect(win, SIGNAL('pin_dialog'), self.pin_dialog)
        self.win.connect(win, SIGNAL('passphrase_dialog'), self.passphrase_dialog)
        self.done = threading.Event()

    def stop(self):
        self.win.emit(SIGNAL('trezor_done'))

    def show_message(self, msg):
        self.message = msg
        self.win.emit(SIGNAL('message_dialog'))

    def get_pin(self, msg):
        self.done.clear()
        self.message = msg
        self.win.emit(SIGNAL('pin_dialog'))
        self.done.wait()
        return self.response

    def get_passphrase(self, msg):
        self.done.clear()
        self.message = msg
        self.win.emit(SIGNAL('passphrase_dialog'))
        self.done.wait()
        return self.passphrase

    def pin_dialog(self):
        d = QDialog(None)
        d.setModal(1)
        d.setWindowTitle(_("Enter PIN"))
        d.setWindowFlags(d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        matrix = PinMatrixWidget()
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(self.message))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)
        if not d.exec_():
            self.response = None
        self.response = str(matrix.get_value())
        self.done.set()

    def passphrase_dialog(self):
        from electrum_gui.qt.password_dialog import make_password_dialog, run_password_dialog
        d = QDialog()
        d.setModal(1)
        d.setLayout(make_password_dialog(d, None, self.message, False))
        confirmed, p, passphrase = run_password_dialog(d, None, None)
        if not confirmed:
            QMessageBox.critical(None, _('Error'), _("Password request canceled"), _('OK'))
            self.passphrase = None
        else:
            if passphrase is None:
                passphrase = '' # Even blank string is valid Trezor passphrase
            self.passphrase = unicodedata.normalize('NFKD', unicode(passphrase))
        self.done.set()

    def message_dialog(self):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('Please Check Trezor Device')
        self.d.setWindowFlags(self.d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        l = QLabel(self.message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.d.show()

    def dialog_stop(self):
        self.d.hide()


if TREZOR:
    class QtGuiTrezorClient(ProtocolMixin, TrezorGuiMixin, BaseClient):
        def call_raw(self, msg):
            try:
                resp = BaseClient.call_raw(self, msg)
            except ConnectionError:
                self.bad = True
                raise
    
            return resp
