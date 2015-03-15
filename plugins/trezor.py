from PyQt4.Qt import QMessageBox, QDialog, QVBoxLayout, QLabel, QThread, SIGNAL, QGridLayout, QInputDialog, QPushButton
import PyQt4.QtCore as QtCore
from binascii import unhexlify
from struct import pack
from sys import stderr
from time import sleep
from base64 import b64encode, b64decode
import unicodedata

import electrum_ltc as electrum
from electrum_ltc.account import BIP32_Account
from electrum_ltc.bitcoin import EncodeBase58Check, public_key_to_bc_address, bc_address_to_hash_160
from electrum_ltc.i18n import _
from electrum_ltc.plugins import BasePlugin, hook
from electrum_ltc.transaction import deserialize
from electrum_ltc.wallet import BIP32_HD_Wallet
from electrum_ltc.util import print_error

from electrum_ltc_gui.qt.util import *

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


def trezor_passphrase_dialog(msg):
    from electrum_ltc_gui.qt.password_dialog import make_password_dialog, run_password_dialog
    d = QDialog()
    d.setModal(1)
    d.setLayout(make_password_dialog(d, None, msg, False))
    confirmed, p, passphrase = run_password_dialog(d, None, None)
    if not confirmed:
        return None
    if passphrase is None:
        passphrase = '' # Even blank string is valid Trezor passphrase
    passphrase = unicodedata.normalize('NFKD', unicode(passphrase))
    return passphrase


class Plugin(BasePlugin):

    def fullname(self):
        return 'Trezor Wallet'

    def description(self):
        return 'Provides support for Trezor hardware wallet\n\nRequires github.com/trezor/python-trezor'

    def __init__(self, config, name):
        BasePlugin.__init__(self, config, name)
        self._is_available = self._init()
        self._requires_settings = True
        self.wallet = None
        if self._is_available:
            electrum.wallet.wallet_types.append(('hardware', 'trezor', _("Trezor wallet"), TrezorWallet))

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

    def enable(self):
        return BasePlugin.enable(self)

    def trezor_is_connected(self):
        try:
            self.wallet.get_client().ping('t')
        except:
            return False
        return True

    @hook
    def init_qt(self, gui):
        self.window = gui.main_window

    @hook
    def close_wallet(self):
        print_error("trezor: clear session")
        if self.wallet and self.wallet.client:
            self.wallet.client.clear_session()
            self.wallet.client.transport.close()

    @hook
    def load_wallet(self, wallet):
        if self.trezor_is_connected():
            if not self.wallet.check_proper_device():
                QMessageBox.information(self.window, _('Error'), _("This wallet does not match your Trezor device"), _('OK'))
                self.wallet.force_watching_only = True
        else:
            QMessageBox.information(self.window, _('Error'), _("Trezor device not detected.\nContinuing in watching-only mode."), _('OK'))
            self.wallet.force_watching_only = True

    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != 'trezor': 
            return
        seed = wizard.enter_seed_dialog("Enter your Trezor seed", None, func=lambda x:True)
        if not seed:
            return
        wallet = TrezorWallet(storage)
        self.wallet = wallet
        passphrase = trezor_passphrase_dialog(_("Please enter your Trezor passphrase.") + '\n' + _("Press OK if you do not use one."))
        if passphrase is None:
            QMessageBox.critical(None, _('Error'), _("Password request canceled"), _('OK'))
            return
        password = wizard.password_dialog()
        wallet.add_seed(seed, password)
        wallet.add_cosigner_seed(seed, 'x/', password, passphrase)
        wallet.create_main_account(password)
        # disable trezor plugin
        self.set_enabled(False)
        return wallet

    @hook
    def send_tx(self, tx):
        tx.error = None
        try:
            self.wallet.trezor_sign(tx)
        except Exception as e:
            tx.error = str(e)
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
            twd.start("Please confirm label change on Trezor")
            status = self.wallet.get_client().apply_settings(label=new_label)
            twd.stop()
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


from electrum_ltc.wallet import pw_decode, bip32_private_derivation, bip32_root

class TrezorWallet(BIP32_HD_Wallet):
    wallet_type = 'trezor'
    root_derivation = "m/44'/2'"

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
        return "44'/2'/%s'/%d/%d" % (account_id, change, address_index)

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
            derivation = derivation.replace(self.root_name,"44'/2'/")
            xpub = self.get_public_key(derivation)
            return xpub, None

    def get_public_key(self, bip32_path):
        address_n = self.get_client().expand_path(bip32_path)
        node = self.get_client().get_public_node(address_n).node
        xpub = "019DA462".decode('hex') + chr(node.depth) + self.i4b(node.fingerprint) + self.i4b(node.child_num) + node.chain_code + node.public_key
        return EncodeBase58Check(xpub)

    def get_master_public_key(self):
        if not self.mpk:
            self.mpk = self.get_public_key("44'/2'")
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
        #    twd.emit(SIGNAL('trezor_done'))
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
            self.get_client().get_address('Litecoin', address_n, True)
        except Exception, e:
            give_error(e)
        finally:
            twd.emit(SIGNAL('trezor_done'))

    def sign_message(self, address, message, password):
        if not self.check_proper_device():
            give_error('Wrong device or password')
        try:
            address_path = self.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception, e:
            give_error(e)
        try:
            msg_sig = self.get_client().sign_message('Litecoin', address_n, message)
        except Exception, e:
            give_error(e)
        finally:
            twd.emit(SIGNAL('trezor_done'))
        b64_msg_sig = b64encode(msg_sig.signature)
        return str(b64_msg_sig)

    def sign_transaction(self, tx, password):
        # the tx is signed by trezor_sign, in the GUI thread
        if tx.error:
            raise BaseException(tx.error)

    def trezor_sign(self, tx):
        if tx.is_complete():
            return
        if not self.check_proper_device():
            give_error('Wrong device or password')

        inputs = self.tx_inputs(tx)
        outputs = self.tx_outputs(tx)
        try:
            signed_tx = self.get_client().sign_tx('Litecoin', inputs, outputs)[1]
        except Exception, e:
            give_error(e)
        finally:
            twd.emit(SIGNAL('trezor_done'))
        values = [i['value'] for i in tx.inputs]
        raw = signed_tx.encode('hex')
        tx.update(raw)
        for i, txinput in enumerate(tx.inputs):
            txinput['value'] = values[i]

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
            if addrtype == 48:
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
        return self.electrum_tx_to_txtype(tx)

    def check_proper_device(self):
        self.get_client().ping('t')
        if not self.device_checked:
            address = self.addresses(False)[0]
            address_id = self.address_id(address)
            n = self.get_client().expand_path(address_id)
            device_address = self.get_client().get_address('Litecoin', n)
            self.device_checked = True

            if device_address != address:
                self.proper_device = False
            else:
                self.proper_device = True

        return self.proper_device


class TrezorQtGuiMixin(object):

    def __init__(self, *args, **kwargs):
        super(TrezorQtGuiMixin, self).__init__(*args, **kwargs)

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
        twd.start(message)
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

        pin = self.pin_dialog(msg="Please enter Trezor %s" % desc)
        if not pin:
            return proto.Cancel()
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        msg = _("Please enter your Trezor passphrase.")
        passphrase = trezor_passphrase_dialog(msg)
        if passphrase is None:
            QMessageBox.critical(None, _('Error'), _("Password request canceled"), _('OK'))
            return proto.Cancel()
        return proto.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        #TODO
        log("Enter one word of mnemonic: ")
        word = raw_input()
        return proto.WordAck(word=word)

    def pin_dialog(self, msg):
        d = QDialog(None)
        d.setModal(1)
        d.setWindowTitle(_("Enter PIN"))
        d.setWindowFlags(d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        matrix = PinMatrixWidget()

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(msg))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)

        if not d.exec_(): return
        return str(matrix.get_value())

class TrezorWaitingDialog(QThread):
    def __init__(self):
        QThread.__init__(self)
        self.waiting = False

    def start(self, message):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('Please Check Trezor Device')
        self.d.setWindowFlags(self.d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        l = QLabel(message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)
        self.d.show()
        if not self.waiting:
            self.waiting = True
            self.d.connect(twd, SIGNAL('trezor_done'), self.stop)

    def stop(self):
        self.d.hide()
        self.waiting = False


if TREZOR:
    class QtGuiTrezorClient(ProtocolMixin, TrezorQtGuiMixin, BaseClient):
        def call_raw(self, msg):
            try:
                resp = BaseClient.call_raw(self, msg)
            except ConnectionError:
                self.bad = True
                raise
    
            return resp

    twd = TrezorWaitingDialog()

