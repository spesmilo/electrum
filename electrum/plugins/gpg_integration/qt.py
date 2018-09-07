# GPG integration - uses blockchain private keys as GPG keys
# Copyright (C) 2018 Dmitry Sorokin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import pathlib
import shutil
from typing import Union

import gnupg
from hashlib import sha1

from electrum.ecc import point_to_ser, ser_to_point
from electrum.i18n import _
from electrum.plugin import BasePlugin, hook

from electrum.bitcoin import bip32_private_derivation, deserialize_xprv, deserialize_xpub, pubkey_to_address, \
    bip32_public_derivation
from electrum.util import bh2u, bfh
from electrum.wallet import Abstract_Wallet

from PyQt5.QtGui import QIcon, QFontDatabase
from PyQt5.QtWidgets import QPushButton, QGridLayout, QTextEdit, QLabel, QHBoxLayout, QTabWidget, QWidget

from ...gui.qt import WindowModalDialog
from ...gui.qt.password_dialog import PasswordDialog


class GPGwrapper:
    def __init__(self) -> None:
        self.home_dir = pathlib.Path('/tmp/electrumgpg/')
        self.pk_dir = self.home_dir / 'private-keys-v1.d'
        self.default_key = None
        self._gpg = gnupg.GPG(gnupghome=self.home_dir.as_posix())
        self._gpg.encoding = 'utf8'
        self.close()

    def close(self):
        self.default_key = None
        if self.home_dir.exists():
            shutil.rmtree(str(self.home_dir))

    def get_key_fpr(self) -> Union[str, None]:
        if self.default_key:
            return self.default_key
        else:
            return None

    def export_pubkey(self):
        out = self._gpg.export_keys(self.default_key)
        return out

    def sign(self, string: str) -> str:
        res = self._gpg.sign(string.encode('utf8'), keyid=self.default_key, clearsign=False)
        return res.data.decode('ascii')

    def verify(self, armored_data: str) -> (bool, str):
        data = armored_data.encode('ascii')
        verify_result = self._gpg.verify(data)
        decrypted_text = self._gpg.decrypt(data)
        string = decrypted_text.data
        try:
            string = string.decode('utf8')
        except UnicodeDecodeError:
            string = 'Invalid encoding: ' + str(string)

        if (
                self.default_key == verify_result.fingerprint) and verify_result:  # verify_result in bool context represent validity
            return True, string
        else:
            return False, string

    def import_recipient_key(self, armored_key: str) -> Union[str, None]:
        res = self._gpg.import_keys(armored_key)
        if len(res.fingerprints) != 1:
            return None
        else:
            return res.fingerprints[0]

    def encrypt(self, plaintext: str, recipient_fpr: str) -> str:
        crypt = self._gpg.encrypt(plaintext.encode('utf8'), [recipient_fpr])
        ciphertext = crypt.data
        return ciphertext.decode('ascii')

    def decrypt(self, armored_ciphertext: str) -> Union[str, None]:
        crypt = self._gpg.decrypt(armored_ciphertext.encode('ascii'))
        plaintext = crypt.data
        if crypt.ok:
            return plaintext.decode('utf8')
        else:
            return None

    def import_ecc_key_to_gpg(self, privkey: str, pubkey: str) -> bool:
        assert len(pubkey) == 130
        assert len(privkey) == 64

        param_key = [
            # Prime
            ("p", 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F),
            # Coefficient A
            ("a", 0x0000000000000000000000000000000000000000000000000000000000000000),
            # Coefficient B
            ("b", 0x0000000000000000000000000000000000000000000000000000000000000007),
            # Generator in 04 || x || y format
            ("g",
             0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
            # Order of generator
            ("n", 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141),
        ]

        def compute_keygrip(k):
            md = sha1()
            for e in k:
                (e_name, e_value) = e
                if e_value == -1:
                    l = 0
                    s = ""
                else:
                    l = (e_value.bit_length() + 7) // 8
                    s = e_value.to_bytes(l, byteorder='big')
                v = "(1:%s%d:" % (e_name, l)
                vb = v.encode('utf-8') + s + b")"
                md.update(vb)
            return md.digest()

        GCRYPT_SEXP_FMT = "(private-key(ecc(curve secp256k1)(q #%s#)(d #%s#)))"
        keydata_str = GCRYPT_SEXP_FMT % (pubkey, privkey)

        param_key.append(('q', int.from_bytes(bfh(pubkey), 'big')))
        grip = bh2u(compute_keygrip(param_key)).upper()

        self.pk_dir.mkdir(parents=True, exist_ok=True)
        keygrip = self.pk_dir / (grip + '.key')
        keygrip.open('w').write(keydata_str)
        key_spec = '''
%echo Generating a secp256k1 OpenPGP key ECDSA and subkey ECDH from {0}
Key-Type:  ECDSA
Key-Grip:  {0}
Key-Curve: secp256k1
Key-Usage: sign,auth
Creation-Date: 20171105T000000Z
Name-Real: bitcoin
Name-Email: bitcoin@bitcoin.key
# Name-Comment:
Expire-Date: 0
Subkey-Type:  ECDH
Subkey-Grip:  {0}
Subkey-Curve: secp256k1
Subkey-Usage: encrypt
# Passphrase: abc
%commit
%echo done
        '''
        key_spec = key_spec.format(grip)

        try:
            key = self._gpg.gen_key(key_spec)
            self.default_key = key.fingerprint
        except Exception as e:
            return False
        return True


class Plugin(BasePlugin):
    button_label = _('GPG export key')

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallet = None
        self.window = None
        self.address = None
        self.export_ok = None
        self.gpgw = GPGwrapper()

    @hook
    def load_wallet(self, wallet: Abstract_Wallet, _):
        if not self.wallet:
            self.wallet = wallet

    @hook
    def close_wallet(self, wallet):
        if self.wallet is wallet:
            self.gpgw.close()
            self.wallet = None

    @hook
    def init_menubar_tools(self, main_window, tools_menu):
        self.main_window = main_window
        tools_menu.addSeparator()
        tools_menu.addAction(_("&GPG tools"), self.show_tools_window)

    def show_tools_window(self):

        fpr = self.gpgw.get_key_fpr()
        if fpr is None:
            self.export_bitcoin_key_dialog()
            if not self.export_ok:
                return
            fpr = self.gpgw.get_key_fpr()
        self.address = self._get_key_address()
        d = WindowModalDialog(self.main_window, _('GPG tools'))
        d.setMinimumSize(900, 490)
        self.window = d

        layout = QGridLayout(d)

        layout.addWidget(QLabel(_('Address (m/0/0):')), 1, 0)
        layout.addWidget(QLabel(self.address), 1, 1)
        layout.addWidget(QLabel(_('GPG key fingerprint:')), 2, 0)
        layout.addWidget(QLabel(fpr), 2, 1)

        tabs = QTabWidget(d)
        tabs.addTab(self.create_signature_tab(), QIcon(':icons/seal.png'), _('Sign/Verify'))
        tabs.addTab(self.create_encrypt_tab(), QIcon(':icons/lock.png'), _('Encrypt/Decrypt'))
        tabs.addTab(self.create_key_info_tab(), QIcon(':icons/key.png'), _('Show GPG key'))

        layout.addWidget(tabs, 3, 0, 1, 2)
        layout.setRowStretch(20, 2)

        b = QPushButton(_('Close'))
        b.clicked.connect(d.accept)
        layout.addWidget(b, 4, 0, 1, 2)
        layout.setRowStretch(1, 2)

        d.exec_()
        self.gpgw.close()

    def create_signature_tab(self):
        w = QWidget()

        layout = QGridLayout(w)

        message_e = QTextEdit()
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2, 2)

        encrypted_e = QTextEdit()
        encrypted_e.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        layout.addWidget(QLabel(_('Signed')), 2, 0)
        layout.addWidget(encrypted_e, 2, 1)
        layout.setRowStretch(2, 2)

        hbox = QHBoxLayout()
        b = QPushButton(_('Sign'))
        b.clicked.connect(lambda: self.do_sign(message_e, encrypted_e))
        hbox.addWidget(b)

        b = QPushButton(_('Verify'))
        b.clicked.connect(lambda: self.do_verify(encrypted_e, message_e))
        hbox.addWidget(b)

        layout.addLayout(hbox, 3, 1)
        return w

    def do_sign(self, input_e: QTextEdit, output_e: QTextEdit) -> None:
        input = input_e.toPlainText().strip()
        output = self.gpgw.sign(input)
        output_e.setPlainText(output)

    def do_verify(self, input_e: QTextEdit, output_e: QTextEdit) -> None:
        input = input_e.toPlainText().strip()
        verified, signed_data = self.gpgw.verify(input)
        output_e.setPlainText(signed_data)

        if verified:
            self.main_window.show_message(_('Signature valid'))
        else:
            self.main_window.show_error(_('Wrong signature'))

    def create_encrypt_tab(self):
        w = QWidget()

        layout = QGridLayout(w)

        message_e = QTextEdit()
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2, 2)

        recipient_e = QTextEdit()
        recipient_e.setPlaceholderText('''-----BEGIN PGP PUBLIC KEY BLOCK-----''')
        recipient_e.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        layout.addWidget(QLabel(_('Recipient key')), 2, 0)
        layout.addWidget(recipient_e, 2, 1)

        encrypted_e = QTextEdit()
        encrypted_e.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        layout.addWidget(QLabel(_('Encrypted')), 3, 0)
        layout.addWidget(encrypted_e, 3, 1)
        layout.setRowStretch(3, 1)

        hbox = QHBoxLayout()
        b = QPushButton(_('Encrypt'))
        b.clicked.connect(lambda: self.do_encrypt(message_e, recipient_e, encrypted_e))
        hbox.addWidget(b)

        b = QPushButton(_('Decrypt'))
        b.clicked.connect(lambda: self.do_decrypt(encrypted_e, message_e))
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
        return w

    def do_encrypt(self, input_e: QTextEdit, recipient_e: QTextEdit, output_e: QTextEdit) -> None:
        message = input_e.toPlainText().strip()
        recipient_key = recipient_e.toPlainText()
        if len(recipient_key) == 0:
            self.main_window.show_error(_('You must specify recipient public key'))
        recipient_fpr = self.gpgw.import_recipient_key(recipient_key)
        if recipient_fpr is None:
            self.main_window.show_error(_('Invalid recipient key'))
        output = self.gpgw.encrypt(message, recipient_fpr)
        output_e.setPlainText(output)

    def do_decrypt(self, input_e: QTextEdit, output_e: QTextEdit) -> None:
        ciphertext = input_e.toPlainText().strip()
        message = self.gpgw.decrypt(ciphertext)

        if message is not None:
            output_e.setPlainText(message)
        else:
            output_e.setPlainText('')
            self.main_window.show_error(_('Cannot decrypt'))

    def create_key_info_tab(self):
        w = QWidget()

        layout = QGridLayout(w)

        layout.addWidget(QLabel(_('GPG public key')), 1, 1)

        data_e = QTextEdit()
        data_e.setReadOnly(True)
        data_e.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))

        layout.addWidget(data_e, 2, 1)
        data_e.setPlainText(self.gpgw.export_pubkey())

        return w

    def show_password_dialog(self, msg=None, parent=None):
        parent = parent
        d = PasswordDialog(parent, msg)
        return d.run()

    def protected(self, msg, f):
        password = None
        if self.wallet.has_password():
            password = self.show_password_dialog(msg)
        f(password)

    def _get_key_address(self):
        root_xpub = self.wallet.keystore.xpub
        xpub = bip32_public_derivation(root_xpub, 'm/', 'm/0/0')
        pubk = bh2u(point_to_ser(ser_to_point(bfh(self._xpub_to_gpg_pub(xpub))), compressed=True))
        addr = pubkey_to_address('p2pkh', pubk)
        return addr

    def export_bitcoin_key_dialog(self):

        def _export(password):
            if not password:
                return
            try:
                xprv = self.wallet.keystore.get_master_private_key(password)
                pk, pubk = self._get_gpg_ecc_compat_keys(xprv)
            except Exception as e:
                self.main_window.show_error(str(e))
                return
            ok = self.gpgw.import_ecc_key_to_gpg(pk, pubk)
            self.export_ok = ok

        self.protected(_('Please enter your password'), _export)

    @staticmethod
    def _xpub_to_gpg_pub(xpub: str) -> str:
        _, _, _, _, _, pubk = deserialize_xpub(xpub)
        pubkey = bh2u(point_to_ser(ser_to_point(pubk), compressed=False))
        return pubkey

    @classmethod
    def _get_gpg_ecc_compat_keys(cls, xprv) -> (str, str):
        xprv, xpub = bip32_private_derivation(xprv, 'm/', 'm/0/0')
        _, _, _, _, c, pk = deserialize_xprv(xprv)
        pk = bh2u(pk)
        pubk = cls._xpub_to_gpg_pub(xpub)
        return pk, pubk


# TODO: move to tests?
xk = {
    'xprv': 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
    'xpub': 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
    'xtype': 'standard'
}
xprv = xk['xprv']
pk, pubk = Plugin._get_gpg_ecc_compat_keys(xprv)
assert pk == '9dc530e4ff0d095e28e25bd2dcc935016e83c89883abca9152639a1d772a2c2a'
assert pubk == '0441902f19a43d5f3147cf23926374d99a0facaad4a3acfbaff9edadbe1ea92a549057b1a1b9c04c1c7f3171a9c5d28086381f5312f3a0317420ecdc39296d1fb8'
