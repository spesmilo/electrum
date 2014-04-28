from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum.i18n import _
from electrum import Wallet, Wallet_2of3

import seed_dialog
from network_dialog import NetworkDialog
from util import *
from amountedit import AmountEdit

import sys
import threading
from electrum.plugins import run_hook

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

        grid = QGridLayout()
        grid.setSpacing(5)

        msg = _("Electrum could not find an existing wallet.") + "\n\n" \
            + _("What do you want to do?") + "\n"
        label = QLabel(msg)
        label.setWordWrap(True)
        grid.addWidget(label, 0, 0)

        gb = QGroupBox()

        b1 = QRadioButton(gb)
        b1.setText(_("Create new wallet"))
        b1.setChecked(True)

        b2 = QRadioButton(gb)
        b2.setText(_("Restore an existing wallet"))

        grid.addWidget(b1,1,0)
        grid.addWidget(b2,2,0)

        vbox = QVBoxLayout()
        self.set_layout(vbox)

        vbox.addLayout(grid)
        vbox.addStretch(1)
        vbox.addLayout(ok_cancel_buttons(self, _('Next')))

        if not self.exec_():
            return
        
        return 'create' if b1.isChecked() else 'restore'



    def verify_seed(self, seed, sid):
        r = self.enter_seed_dialog(False, sid)
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


    def is_seed(self, seed_e):
        text = self.get_seed_text(seed_e)
        return Wallet.is_seed(text) or Wallet.is_mpk(text)


    def enter_seed_dialog(self, is_restore, sid):
        vbox, seed_e = seed_dialog.enter_seed_box(is_restore, sid)
        vbox.addStretch(1)
        hbox, button = ok_cancel_buttons2(self, _('Next'))
        vbox.addLayout(hbox)
        button.setEnabled(False)
        seed_e.textChanged.connect(lambda: button.setEnabled(self.is_seed(seed_e)))
        self.set_layout(vbox)
        if not self.exec_():
            return
        return self.get_seed_text(seed_e)


    def double_seed_dialog(self):
        vbox = QVBoxLayout()
        vbox1, seed_e1 = seed_dialog.enter_seed_box(True, 'hot')
        vbox2, seed_e2 = seed_dialog.enter_seed_box(True, 'cold')
        vbox.addLayout(vbox1)
        vbox.addLayout(vbox2)
        vbox.addStretch(1)
        hbox, button = ok_cancel_buttons2(self, _('Next'))
        vbox.addLayout(hbox)
        button.setEnabled(False)
        f = lambda: button.setEnabled(self.is_seed(seed_e1) and self.is_seed(seed_e2))
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


    def choose_wallet_type(self):
        grid = QGridLayout()
        grid.setSpacing(5)

        msg = _("Choose your wallet.")
        label = QLabel(msg)
        label.setWordWrap(True)
        grid.addWidget(label, 0, 0)

        gb = QGroupBox()

        b1 = QRadioButton(gb)
        b1.setText(_("Standard wallet (protected by password)"))
        b1.setChecked(True)

        b2 = QRadioButton(gb)
        b2.setText(_("Multi-signature wallet (two-factor authentication)"))

        grid.addWidget(b1,1,0)
        grid.addWidget(b2,2,0)

        vbox = QVBoxLayout()

        vbox.addLayout(grid)
        vbox.addStretch(1)
        vbox.addLayout(ok_cancel_buttons(self, _('Next')))

        self.set_layout(vbox)
        if not self.exec_():
            return
        
        if b1.isChecked():
            return 'standard'
        elif b2.isChecked():
            return '2of3'


    def run(self, action = None):

        if action is None:
            action = self.restore_or_create()

        if action is None: 
            return

        if action == 'create':            
            t = self.choose_wallet_type()
            if not t:
                return 

            if t == '2of3':
                run_hook('create_cold_seed', self.storage, self)
                return


        if action in ['create', 'create2of3']:

            wallet = Wallet(self.storage)
            seed = wallet.make_seed()
            sid = 'hot' if action == 'create2of3' else None
            if not self.show_seed(seed, sid):
                return
            if not self.verify_seed(seed, sid):
                return
            password = self.password_dialog()
            wallet.add_seed(seed, password)

            if action == 'create2of3':
                run_hook('create_third_key', wallet, self)
                if not wallet.master_public_keys.get("remote/"):
                    return

            wallet.create_accounts(password)
            # generate first addresses offline
            self.waiting_dialog(wallet.synchronize)

        elif action == 'restore':
            t = self.choose_wallet_type()
            if not t: 
                return

            if t == 'standard':
                text = self.enter_seed_dialog(True, None)
                if Wallet.is_seed(text):
                    password = self.password_dialog()
                    wallet = Wallet.from_seed(text, self.storage)
                    wallet.add_seed(text, password)
                    wallet.create_accounts(password)
                elif Wallet.is_mpk(text):
                    wallet = Wallet.from_mpk(text, self.storage)
                else:
                    raise

            elif t in ['2of2', '2of3']:
                r = self.double_seed_dialog()
                if not r: 
                    return
                text1, text2 = r
                password = self.password_dialog()
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

                run_hook('restore_third_key', wallet, self)

                wallet.create_accounts(None)

            else:
                raise




        else: raise
                
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
