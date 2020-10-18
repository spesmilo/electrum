# -*- mode: python3 -*-
# Electron Cash - (C) 2019 The Electron Cash Developers and Electron Cash LLC
#
import threading

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .util import *

from electroncash.i18n import _
from electroncash import util, bitcoin, address

class Bip38Importer(WindowModalDialog, util.PrintError):
    ''' A drop-in GUI element for implementing a BIP38 import dialog.
    For each of the passed-in bip38 keys, it will prompt the user to enter their
    password and it will attempt to decrypt the keys.
    Requires bitcoin.is_bip38_available() == True otherwise will raise
    RuntimeError on instantiation. '''

    decrypted_sig = pyqtSignal(object, object)  # Decrypt thread emits this with _decrypt_thread.self, (decrypted_wif, Address) or _decrypt_thread.self, () on failure due to bad password

    def __init__(self, bip38_keys, *,
                 parent=None, title=None,
                 message=None,  # The message to display as a label up top
                 show_count=True, # If false, don't show 'Key 1/n:' in UI instead just say: 'Key: '
                 on_success=None,  # Callback will be called with a dict of bip38key -> (decoded_wif_str, Address) objects
                 on_cancel=None):  # Callback will be called if user hits cancel
        ''' bip38_keys should be a list of '6P' strings, representing bip38
        keys. The user will be prompted for each key to enter a password
        and will be shown the decoded address and WIF key. Note that this
        method will raise RuntimeError if not bitcion.is_bip38_available().

        on_success: if specified, will be called after the window has closed
                    (exec_ has finished) with a single argument: a dict of
                    bip38key -> (decoded_wif, Address).
        on_cancel:  if specified, will be called after the window was closed
                    (exec_ has finished) with no arguments.

        If you don't specify any callbacks, results are still available in
        the self.decoded_keys dict.

        The dialog will always terminate with either all keys successfully
        decrypted or a user cancel.
        '''
        if not title:
            title = 'Electron Cash - ' + _('BIP38 Import')
        WindowModalDialog.__init__(self, parent=parent, title=title)
        if not bitcoin.is_bip38_available():
            raise RuntimeError('Bip38Importer: bip38 decoding is not available')
        self.bip38_keys = tuple(bip38_keys)
        assert self.bip38_keys and all(bitcoin.is_bip38_key(k) for k in self.bip38_keys)
        if not parent:
            self.setWindowModality(Qt.ApplicationModal)

        self.decoded_keys = dict()  # results are placed here on success
        self.success_cb, self.cancel_cb = on_success, on_cancel
        self.cur, self.decoded_wif, self.decoded_address = 0, None, None
        self.decrypter = None
        self.show_count = show_count

        self.decrypted_sig.connect(self.on_decrypted)

        self._setup_ui(message)

        util.finalization_print_error(self)

    def _setup_ui(self, message=None):
        num = len(self.bip38_keys)
        if message is None:
            message = _('{} BIP38 keys were detected and require a password to decode').format(num)
        grid = QGridLayout(self)
        grid.setContentsMargins(24,24,24,24)
        grid.setSpacing(10)
        top_title = QLabel('<font size=+1><b>{}</b></font> - {}'
                           .format(_('BIP38 Import'), message), self)
        top_title.setWordWrap(True)

        grid.addWidget(top_title, 0, 0, 1, 2)

        self.key_tit = QLabel('      ', self)
        self.key_lbl = QLabel('      ', self)
        f = self.key_lbl.font()
        f.setBold(True); f.setFamily(MONOSPACE_FONT)
        self.key_lbl.setFont(f)
        self.key_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.TextSelectableByKeyboard)

        grid.addWidget(self.key_tit, 1, 0)
        grid.addWidget(self.key_lbl, 1, 1)

        pw_tit = HelpLabel(_('Password:'),
                           _('BIP38 keys are strongly encrypted with a password. To decode this key, please specify the password you used when creating the key.'))
        self.pw_le = QLineEdit()
        self.pw_le.setEchoMode(QLineEdit.Password)

        timer = QTimer(self)
        timer.setSingleShot(True)

        def start_decrypter():
            if not self.isVisible():
                return
            # starts a new thread. note that the old thread is not cancelled and just allowed to run until completion, with its results ignored
            pw = self.pw_le.text()
            self.decoded_address, self.decoded_wif = ('decrypting', 'decrypting') if pw else (None, None)
            b38key = self.bip38_keys[self.cur]
            self.decoded_keys.pop(b38key, None)
            self.refresh()
            if pw:
                self.decrypter = _decrypt_thread(self, b38key, self.pw_le.text())  # starts a new thread
            else:
                self.decrypter = None

        def on_edit():
            self.ok.setDisabled(True)  # Disable the Next/Ok button right away
            self.decrypter = None # Indicate the current decryptor is totally defunct (its results will now be ignored)
            # re-start the timer to fire in 500 ms. this way there is some
            # delay before we start another decrypter thread, in case the user
            # wants to type more characters
            timer.start(500)

        timer.timeout.connect(start_decrypter)
        self.pw_le.textEdited.connect(on_edit)

        grid.addWidget(pw_tit, 2, 0)
        grid.addWidget(self.pw_le, 2, 1)

        hlp = _('The decrypted private key (WIF key) originally used to create this BIP38 key.')
        wif_tit = HelpLabel(_('Decrypted Private Key:'), hlp)
        self.wif_lbl = QLabel('     ', self)
        self.wif_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.TextSelectableByKeyboard)

        grid.addWidget(wif_tit, 3, 0)
        grid.addWidget(self.wif_lbl, 3, 1)

        hlp = _('The address for the decrypted private key.')
        adr_tit = HelpLabel(_('Address:'), hlp)
        self.adr_lbl = QLabel('    ', self)
        self.adr_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.TextSelectableByKeyboard)

        grid.addWidget(adr_tit, 4, 0)
        grid.addWidget(self.adr_lbl, 4, 1)

        self.ok = OkButton(self)
        cancel = CancelButton(self)

        buttons = Buttons(cancel, self.ok)

        grid.addLayout(buttons, 5, 0, 1, 2)

        self.setLayout(grid)

        self.clear()
        self.refresh()

    def showEvent(self, e):
        super().showEvent(e)
        if e.isAccepted():
            self.cur = 0
            self.clear()
            self.refresh()

    def clear(self):
        self.pw_le.setText('')
        self.decrypter = None
        self.decoded_address, self.decoded_wif = None, None

    def refresh(self):
        num = len(self.bip38_keys)
        cur = self.cur
        self.key_tit.setText(_('Encrypted Key') + ( (' ' + _('({} of {}):').format(cur+1, num)) if self.show_count else ':') )
        self.key_lbl.setText(self.bip38_keys[cur])

        pw_req = _('(password required)') if self.decoded_wif != 'decrypting' else _('decrypting...')
        is_ok = bool(self.decoded_wif and self.decoded_wif not in ('bad', 'decrypting'))
        bad_txt = pw_req if not self.decoded_wif or self.decoded_wif != 'bad' else '<font color={}>{}</font>'.format(ColorScheme.RED._get_color(False), _('password incorrect'))
        # set wif_lbl font
        f = self.wif_lbl.font(); f.setFamily(MONOSPACE_FONT if is_ok else QFont().family()); f.setItalic(not is_ok); self.wif_lbl.setFont(f)
        self.wif_lbl.setText((is_ok and self.decoded_wif) or bad_txt)
        # set adr_lbl font
        f = self.adr_lbl.font(); f.setFamily(MONOSPACE_FONT if is_ok else QFont().family()); f.setItalic(not is_ok); self.adr_lbl.setFont(f)
        self.adr_lbl.setText((is_ok and self.decoded_address.to_ui_string()) or bad_txt)

        self.ok.setEnabled(isinstance(self.decoded_address, address.Address))
        self.ok.setText(_('OK') if cur+1 == num else _("Next"))

    def accept(self):
        ''' Overrides QDialog.accept '''
        num = len(self.bip38_keys)
        self.cur += 1
        if self.cur == num:
            if set(self.bip38_keys) != set(self.decoded_keys.keys()):
                raise RuntimeError("Dialog finished but something's wrong -- not all passed-in keys are in the decoded keys dict. FIXME!")
            self.decrypter = None # just in case a decrypter was running
            super().accept()
            if self.success_cb:
                # we call the callback after we are definitely off-screen
                QTimer.singleShot(250, lambda: self.success_cb(self.decoded_keys.copy()))
        else:
            self.clear()
            self.refresh()

    def reject(self):
        ''' Overrides QDialog.reject '''
        super().reject()
        self.decrypter = None # just in case a decrypter was running
        self.decoded_keys.clear() # indicate to caller it was cancelled.
        if self.cancel_cb:
            # we call the callback after we are definitely off-screen
            QTimer.singleShot(250, lambda: self.cancel_cb())

    def on_decrypted(self, sender, tup):
        if sender is not self.decrypter or not self.isVisible():
            # ignore sender if it's not the currently-active decrypter or if we're already done
            return
        b38key = sender.key
        if b38key != self.bip38_keys[self.cur]:
            self.print_error("Warning: Got a result from decrypter but decrypter.key != self.cur. FIXME!")
            return
        if tup:
            wif, adr = tup
            self.decoded_keys[b38key] = (wif, adr)
            self.decoded_wif = wif
            self.decoded_address = adr
        else:
            self.decoded_keys.pop(b38key, None)
            self.decoded_wif = 'bad'
            self.decoded_address = 'bad'
        self.refresh()

class _decrypt_thread(threading.Thread, util.PrintError):
    ''' Helper for the above Bip38Importer class. Does the computationally
    expensive scrypt-based decode of a bip38 key in another thread in order to
    keep the GUI responsive. Note that we create a new one of these each time
    the user edits the password text edit, and the old ones continue to run
    until they complete, at which point they emit the decrypted_sig.  Only
    the most recent decrypt_thread's results are accepted by the dialog, however.'''

    def __init__(self, w, key, pw):
        super().__init__(daemon=True, target=self.decrypt)
        self.w = util.Weak.ref(w)  # We keep a weak ref to parent because parent may die while we are still running. In which case we don't want to call into parent when it's already closed/done executing
        self.key = key
        self.pw = pw
        self.start()

    def decrypt(self):
        result = bitcoin.bip38_decrypt(self.key, self.pw)  # Potentially slow-ish operation. Note: result may be None or empty; client code's slot checks for that condition, so no need to check result here.
        parent = self.w()  # grab strong ref from weak ref if weak ref still alive
        if parent:
            parent.decrypted_sig.emit(self, result)
        else:
            self.print_error("parent widget was no longer alive, silently ignoring...")
