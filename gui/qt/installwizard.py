from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum.i18n import _
from electrum import Wallet, Wallet_2of2, Wallet_2of3
import electrum.bitcoin as bitcoin

import seed_dialog
from network_dialog import NetworkDialog
from util import *
from amountedit import AmountEdit

import sys
import threading
from electrum.plugins import run_hook


MSG_ENTER_ANYTHING    = _("Please enter a wallet seed, a master public key, a list of Bitcoin addresses, or a list of private keys")
MSG_SHOW_MPK          = _("This is your master public key")
MSG_ENTER_MPK         = _("Please enter your master public key")
MSG_ENTER_COLD_MPK    = _("Please enter the master public key of your cosigning wallet")
MSG_ENTER_SEED_OR_MPK = _("Please enter a wallet seed, or master public key")
MSG_VERIFY_SEED       = _("Your seed is important!") + "\n" + _("To make sure that you have properly saved your seed, please retype it here.")


class InstallWizard(QDialog):

    def __init__(self, config, network, storage):
        QDialog.__init__(self)
        self.config = config
        self.network = network
        self.storage = storage
        self.setMinimumSize(575, 400)
        self.setWindowTitle('Electrum')
        self.connect(self, QtCore.SIGNAL('accept'), self.accept)

        self.stack = QStackedLayout()
        self.setLayout(self.stack)


    def set_layout(self, layout):
        w = QWidget()
        w.setLayout(layout)
        self.stack.setCurrentIndex(self.stack.addWidget(w))


    def restore_or_create(self):

        vbox = QVBoxLayout()

        main_label = QLabel(_("Electrum could not find an existing wallet."))
        vbox.addWidget(main_label)

        grid = QGridLayout()
        grid.setSpacing(5)

        label = QLabel(_("What do you want to do?"))
        label.setWordWrap(True)
        grid.addWidget(label, 0, 0)

        gb1 = QGroupBox()
        grid.addWidget(gb1, 0, 0)

        group1 = QButtonGroup()

        b1 = QRadioButton(gb1)
        b1.setText(_("Create new wallet"))
        b1.setChecked(True)

        b2 = QRadioButton(gb1)
        b2.setText(_("Restore an existing wallet"))

        group1.addButton(b1)
        group1.addButton(b2)

        grid.addWidget(b1, 1, 0)
        grid.addWidget(b2, 2, 0)
        vbox.addLayout(grid)

        grid2 = QGridLayout()
        grid2.setSpacing(5)

        class ClickableLabel(QLabel):
            def mouseReleaseEvent(self, ev):
                self.emit(SIGNAL('clicked()'))

        label2 = ClickableLabel(_("Wallet type:") + " [+]")
        hbox = QHBoxLayout()
        hbox.addWidget(label2)
        grid2.addLayout(hbox, 3, 0)
        
        gb2 = QGroupBox()
        grid.addWidget(gb2, 3, 0)

        group2 = QButtonGroup()

        bb1 = QRadioButton(gb2)
        bb1.setText(_("Standard wallet"))
        bb1.setChecked(True)

        bb2 = QRadioButton(gb2)
        bb2.setText(_("Wallet with two-factor authentication (plugin)"))

        bb3 = QRadioButton(gb2)
        bb3.setText(_("Multisig wallet (2 of 2)"))
        bb3.setHidden(True)

        bb4 = QRadioButton(gb2)
        bb4.setText(_("Multisig wallet (2 of 3)"))
        bb4.setHidden(True)

        grid2.addWidget(bb1, 4, 0)
        grid2.addWidget(bb2, 5, 0)
        grid2.addWidget(bb3, 6, 0)
        grid2.addWidget(bb4, 7, 0)

        def toggle():
            x = not bb3.isHidden()
            label2.setText(_("Wallet type:") + (' [+]' if x else ' [-]'))
            bb3.setHidden(x)
            bb4.setHidden(x)
 
        self.connect(label2, SIGNAL('clicked()'), toggle)

        grid2.addWidget(label2)

        group2.addButton(bb1)
        group2.addButton(bb2)
        group2.addButton(bb3)
        group2.addButton(bb4)
 
        vbox.addLayout(grid2)
        vbox.addStretch(1)
        vbox.addLayout(ok_cancel_buttons(self, _('Next')))

        self.set_layout(vbox)
        if not self.exec_():
            return None, None
        
        action = 'create' if b1.isChecked() else 'restore'

        if bb1.isChecked():
            t = 'standard'
        elif bb2.isChecked():
            t = '2fa'
        elif bb3.isChecked():
            t = '2of2'
        elif bb4.isChecked():
            t = '2of3'

        return action, t


    def verify_seed(self, seed, sid):
        r = self.enter_seed_dialog(MSG_VERIFY_SEED, sid)
        if not r:
            return

        if r != seed:
            QMessageBox.warning(None, _('Error'), _('Incorrect seed'), _('OK'))
            return False
        else:
            return True


    def get_seed_text(self, seed_e):
        text = unicode(seed_e.toPlainText()).strip()
        text = ' '.join(text.split())
        return text


    def is_any(self, seed_e):
        text = self.get_seed_text(seed_e)
        return Wallet.is_seed(text) or Wallet.is_mpk(text) or Wallet.is_address(text) or Wallet.is_private_key(text)

    def is_mpk(self, seed_e):
        text = self.get_seed_text(seed_e)
        return Wallet.is_mpk(text)


    def enter_seed_dialog(self, msg, sid):
        vbox, seed_e = seed_dialog.enter_seed_box(msg, sid)
        vbox.addStretch(1)
        hbox, button = ok_cancel_buttons2(self, _('Next'))
        vbox.addLayout(hbox)
        button.setEnabled(False)
        seed_e.textChanged.connect(lambda: button.setEnabled(self.is_any(seed_e)))
        self.set_layout(vbox)
        if not self.exec_():
            return
        return self.get_seed_text(seed_e)


    def cold_mpk_dialog(self, xpub_hot):
        vbox = QVBoxLayout()
        vbox1, seed_e1 = seed_dialog.enter_seed_box(MSG_SHOW_MPK, 'hot')
        seed_e1.setText(xpub_hot)
        seed_e1.setReadOnly(True)
        vbox2, seed_e2 = seed_dialog.enter_seed_box(MSG_ENTER_COLD_MPK, 'cold')
        vbox.addLayout(vbox1)
        vbox.addLayout(vbox2)
        vbox.addStretch(1)
        hbox, button = ok_cancel_buttons2(self, _('Next'))
        vbox.addLayout(hbox)
        button.setEnabled(False)
        f = lambda: button.setEnabled(self.is_mpk(seed_e2))
        seed_e2.textChanged.connect(f)
        self.set_layout(vbox)
        if not self.exec_():
            return 
        return self.get_seed_text(seed_e2)


    def cold_mpk2_dialog(self, xpub_hot):
        vbox = QVBoxLayout()
        vbox0, seed_e0 = seed_dialog.enter_seed_box(MSG_SHOW_MPK, 'hot')
        seed_e0.setText(xpub_hot)
        seed_e0.setReadOnly(True)
        vbox1, seed_e1 = seed_dialog.enter_seed_box(MSG_ENTER_COLD_MPK, 'cold')
        vbox2, seed_e2 = seed_dialog.enter_seed_box(MSG_ENTER_COLD_MPK, 'cold')
        vbox.addLayout(vbox0)
        vbox.addLayout(vbox1)
        vbox.addLayout(vbox2)
        vbox.addStretch(1)
        hbox, button = ok_cancel_buttons2(self, _('Next'))
        vbox.addLayout(hbox)
        button.setEnabled(False)
        f = lambda: button.setEnabled(self.is_mpk(seed_e1) and self.is_mpk(seed_e2))
        seed_e1.textChanged.connect(f)
        seed_e2.textChanged.connect(f)
        self.set_layout(vbox)
        if not self.exec_():
            return 
        return self.get_seed_text(seed_e1), self.get_seed_text(seed_e2)


    def double_seed_dialog(self):
        vbox = QVBoxLayout()
        vbox1, seed_e1 = seed_dialog.enter_seed_box(MSG_ENTER_SEED_OR_MPK, 'hot')
        vbox2, seed_e2 = seed_dialog.enter_seed_box(MSG_ENTER_SEED_OR_MPK, 'cold')
        vbox.addLayout(vbox1)
        vbox.addLayout(vbox2)
        vbox.addStretch(1)
        hbox, button = ok_cancel_buttons2(self, _('Next'))
        vbox.addLayout(hbox)
        button.setEnabled(False)
        f = lambda: button.setEnabled(self.is_any(seed_e1) and self.is_any(seed_e2))
        seed_e1.textChanged.connect(f)
        seed_e2.textChanged.connect(f)
        self.set_layout(vbox)
        if not self.exec_():
            return 
        return self.get_seed_text(seed_e1), self.get_seed_text(seed_e2)




    def waiting_dialog(self, task, msg= _("Electrum is generating your addresses, please wait.")):
        def target():
            task()
            self.emit(QtCore.SIGNAL('accept'))

        vbox = QVBoxLayout()
        self.waiting_label = QLabel(msg)
        vbox.addWidget(self.waiting_label)
        self.set_layout(vbox)
        t = threading.Thread(target = target)
        t.start()
        self.exec_()




    def network_dialog(self):
        
        grid = QGridLayout()
        grid.setSpacing(5)

        label = QLabel(_("Electrum communicates with remote servers to get information about your transactions and addresses. The servers all fulfil the same purpose only differing in hardware. In most cases you simply want to let Electrum pick one at random if you have a preference though feel free to select a server manually.") + "\n\n" \
                      + _("How do you want to connect to a server:")+" ")
        label.setWordWrap(True)
        grid.addWidget(label, 0, 0)

        gb = QGroupBox()

        b1 = QRadioButton(gb)
        b1.setText(_("Auto connect"))
        b1.setChecked(True)

        b2 = QRadioButton(gb)
        b2.setText(_("Select server manually"))

        #b3 = QRadioButton(gb)
        #b3.setText(_("Stay offline"))

        grid.addWidget(b1,1,0)
        grid.addWidget(b2,2,0)
        #grid.addWidget(b3,3,0)

        vbox = QVBoxLayout()
        vbox.addLayout(grid)

        vbox.addStretch(1)
        vbox.addLayout(ok_cancel_buttons(self, _('Next')))

        self.set_layout(vbox)
        if not self.exec_():
            return
        
        if b2.isChecked():
            return NetworkDialog(self.network, self.config, None).do_exec()

        elif b1.isChecked():
            self.config.set_key('auto_cycle', True, True)
            return

        else:
            self.config.set_key("server", None, True)
            self.config.set_key('auto_cycle', False, True)
            return
        

    def show_message(self, msg, icon=None):
        vbox = QVBoxLayout()
        self.set_layout(vbox)
        if icon:
            logo = QLabel()
            logo.setPixmap(icon)
            vbox.addWidget(logo)
        vbox.addWidget(QLabel(msg))
        vbox.addStretch(1)
        vbox.addLayout(close_button(self, _('Next')))
        if not self.exec_(): 
            return None


    def question(self, msg, icon=None):
        vbox = QVBoxLayout()
        self.set_layout(vbox)
        if icon:
            logo = QLabel()
            logo.setPixmap(icon)
            vbox.addWidget(logo)
        vbox.addWidget(QLabel(msg))
        vbox.addStretch(1)
        vbox.addLayout(ok_cancel_buttons(self, _('OK')))
        if not self.exec_(): 
            return None
        return True


    def show_seed(self, seed, sid):
        vbox = seed_dialog.show_seed_box(seed, sid)
        vbox.addLayout(ok_cancel_buttons(self, _("Next")))
        self.set_layout(vbox)
        return self.exec_()


    def password_dialog(self):
        msg = _("Please choose a password to encrypt your wallet keys.")+'\n'\
              +_("Leave these fields empty if you want to disable encryption.")
        from password_dialog import make_password_dialog, run_password_dialog
        self.set_layout( make_password_dialog(self, None, msg) )
        return run_password_dialog(self, None, self)[2]


    def create_cold_seed(self, wallet):
        from electrum.bitcoin import mnemonic_to_seed, bip32_root
        msg = _('You are about to generate the cold storage seed of your wallet.') + '\n' \
              + _('For safety, you should do this on an offline computer.')
        icon = QPixmap( ':icons/cold_seed.png').scaledToWidth(56)
        if not self.question(msg, icon):
            return

        cold_seed = wallet.make_seed()
        if not self.show_seed(cold_seed, 'cold'):
            return
        if not self.verify_seed(cold_seed, 'cold'):
            return

        hex_seed = mnemonic_to_seed(cold_seed,'').encode('hex')
        xpriv, xpub = bip32_root(hex_seed)
        wallet.add_master_public_key('cold/', xpub)

        msg = _('Your master public key was saved in your wallet file.') + '\n'\
              + _('Your cold seed must be stored on paper; it is not in the wallet file.')+ '\n\n' \
              + _('This program is about to close itself.') + '\n'\
              + _('You will need to reopen your wallet on an online computer, in order to complete the creation of your wallet')
        self.show_message(msg)



    def run(self, action):

        if action == 'new':
            action, t = self.restore_or_create()

        if action is None: 
            return
            
        if action == 'create':
            if t == 'standard':
                wallet = Wallet(self.storage)

            elif t == '2fa':
                wallet = Wallet_2of3(self.storage)
                run_hook('create_cold_seed', wallet, self)
                self.create_cold_seed(wallet)
                return

            elif t == '2of2':
                wallet = Wallet_2of2(self.storage)
                action = 'create_2of2_1'

            elif t == '2of3':
                wallet = Wallet_2of3(self.storage)
                action = 'create_2of3_1'


        if action == 'create_2fa_2':
            wallet = Wallet_2of3(self.storage)

        if action in ['create', 'create_2of2_1', 'create_2fa_2', 'create_2of3_1']:
            seed = wallet.make_seed()
            sid = None if action == 'create' else 'hot'
            if not self.show_seed(seed, sid):
                return
            if not self.verify_seed(seed, sid):
                return
            password = self.password_dialog()
            wallet.add_seed(seed, password)
            if action == 'create':
                wallet.create_accounts(password)
                self.waiting_dialog(wallet.synchronize)
            elif action == 'create_2of2_1':
                action = 'create_2of2_2'
            elif action == 'create_2of3_1':
                action = 'create_2of3_2'
            elif action == 'create_2fa_2':
                action = 'create_2fa_3'

        if action == 'create_2of2_2':
            xpub_hot = wallet.master_public_keys.get("m/")
            xpub = self.cold_mpk_dialog(xpub_hot)
            wallet.add_master_public_key("cold/", xpub)
            wallet.create_account()
            self.waiting_dialog(wallet.synchronize)


        if action == 'create_2of3_2':
            xpub_hot = wallet.master_public_keys.get("m/")
            xpub1, xpub2 = self.cold_mpk2_dialog(xpub_hot)
            wallet.add_master_public_key("cold/", xpub1)
            wallet.add_master_public_key("remote/", xpub2)
            wallet.create_account()
            self.waiting_dialog(wallet.synchronize)


        if action == 'create_2fa_3':
            run_hook('create_remote_key', wallet, self)
            if not wallet.master_public_keys.get("remote/"):
                return
            wallet.create_account()
            self.waiting_dialog(wallet.synchronize)


        if action == 'restore':

            if t == 'standard':
                text = self.enter_seed_dialog(MSG_ENTER_ANYTHING, None)
                if not text:
                    return
                if Wallet.is_seed(text):
                    password = self.password_dialog()
                    wallet = Wallet.from_seed(text, self.storage)
                    wallet.add_seed(text, password)
                    wallet.create_accounts(password)
                elif Wallet.is_mpk(text):
                    wallet = Wallet.from_mpk(text, self.storage)
                elif Wallet.is_address(text):
                    wallet = Wallet.from_address(text, self.storage)
                elif Wallet.is_private_key(text):
                    wallet = Wallet.from_private_key(text, self.storage)
                else:
                    raise

            elif t in ['2fa', '2of2','2of3']:
                r = self.double_seed_dialog()
                if not r: 
                    return
                text1, text2 = r
                password = self.password_dialog()
                if t == '2of2':
                    wallet = Wallet_2of2(self.storage)
                elif t == '2of3':
                    wallet = Wallet_2of3(self.storage)
                elif t == '2fa':
                    wallet = Wallet_2of3(self.storage)

                if Wallet.is_seed(text1):
                    wallet.add_seed(text1, password)
                    if Wallet.is_seed(text2):
                        wallet.add_cold_seed(text2, password)
                    else:
                        wallet.add_master_public_key("cold/", text2)

                elif Wallet.is_mpk(text1):
                    if Wallet.is_seed(text2):
                        wallet.add_seed(text2, password)
                        wallet.add_master_public_key("cold/", text1)
                    else:
                        wallet.add_master_public_key("m/", text1)
                        wallet.add_master_public_key("cold/", text2)

                if t == '2of3':
                    run_hook('restore_third_key', wallet, self)

                wallet.create_account()

            else:
                raise


                
        #if not self.config.get('server'):
        if self.network:
            if self.network.interfaces:
                self.network_dialog()
            else:
                QMessageBox.information(None, _('Warning'), _('You are offline'), _('OK'))
                self.network.stop()
                self.network = None

        # start wallet threads
        wallet.start_threads(self.network)

        if action == 'restore':

            self.waiting_dialog(lambda: wallet.restore(self.waiting_label.setText))

            if self.network:
                if wallet.is_found():
                    QMessageBox.information(None, _('Information'), _("Recovery successful"), _('OK'))
                else:
                    QMessageBox.information(None, _('Information'), _("No transactions found for this seed"), _('OK'))
            else:
                QMessageBox.information(None, _('Information'), _("This wallet was restored offline. It may contain more addresses than displayed."), _('OK'))

        return wallet
