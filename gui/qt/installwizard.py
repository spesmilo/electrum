from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

import electrum_ltc as electrum
from electrum_ltc.i18n import _
from electrum_ltc import Wallet, Wallet_2of2, Wallet_2of3
from electrum_ltc import bitcoin
from electrum_ltc import util

import seed_dialog
from network_dialog import NetworkDialog
from util import *
from amountedit import AmountEdit

import sys
import threading
from electrum_ltc.plugins import run_hook
from electrum_ltc.mnemonic import prepare_seed

MSG_ENTER_ANYTHING    = _("Please enter a wallet seed, a master public key, a list of Litecoin addresses, or a list of private keys")
MSG_SHOW_MPK          = _("This is your master public key")
MSG_ENTER_MPK         = _("Please enter your master public key")
MSG_ENTER_COLD_MPK    = _("Please enter the master public key of your cosigner wallet")
MSG_ENTER_SEED_OR_MPK = _("Please enter a wallet seed, BIP32 private key, or master public key")
MSG_VERIFY_SEED       = _("Your seed is important!") + "\n" + _("To make sure that you have properly saved your seed, please retype it here.")


class InstallWizard(QDialog):

    def __init__(self, config, network, storage):
        QDialog.__init__(self)
        self.config = config
        self.network = network
        self.storage = storage
        self.setMinimumSize(575, 400)
        self.setMaximumSize(575, 400)
        self.setWindowTitle('Electrum' + '  -  ' + os.path.basename(self.storage.path))
        self.connect(self, QtCore.SIGNAL('accept'), self.accept)
        self.stack = QStackedLayout()
        self.setLayout(self.stack)

    def set_layout(self, layout):
        w = QWidget()
        w.setLayout(layout)
        self.stack.addWidget(w)
        self.stack.setCurrentWidget(w)
        self.show()

    def restore_or_create(self):
        vbox = QVBoxLayout()
        main_label = QLabel(_("Electrum could not find an existing wallet."))
        vbox.addWidget(main_label)
        grid = QGridLayout()
        grid.setSpacing(5)
        gb1 = QGroupBox(_("What do you want to do?"))
        vbox.addWidget(gb1)
        b1 = QRadioButton(gb1)
        b1.setText(_("Create new wallet"))
        b1.setChecked(True)
        b2 = QRadioButton(gb1)
        b2.setText(_("Restore a wallet or import keys"))
        group1 = QButtonGroup()
        group1.addButton(b1)
        group1.addButton(b2)
        vbox.addWidget(b1)
        vbox.addWidget(b2)

        gb2 = QGroupBox(_("Wallet type:"))
        vbox.addWidget(gb2)
        group2 = QButtonGroup()

        self.wallet_types = [
            ('standard',  _("Standard wallet")),
            ('twofactor', _("Wallet with two-factor authentication")),
            ('multisig',  _("Multi-signature wallet")),
            ('hardware',  _("Hardware wallet")),
        ]

        for i, (wtype,name) in enumerate(self.wallet_types):
            if not filter(lambda x:x[0]==wtype, electrum.wallet.wallet_types):
                continue
            button = QRadioButton(gb2)
            button.setText(name)
            vbox.addWidget(button)
            group2.addButton(button)
            group2.setId(button, i)
            if i==0:
                button.setChecked(True)

        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _('Next'))))
        self.set_layout(vbox)
        self.show()
        self.raise_()

        if not self.exec_():
            return None, None

        action = 'create' if b1.isChecked() else 'restore'
        wallet_type = self.wallet_types[group2.checkedId()][0]
        return action, wallet_type


    def verify_seed(self, seed, sid, func=None):
        r = self.enter_seed_dialog(MSG_VERIFY_SEED, sid, func)
        if not r:
            return
        if prepare_seed(r) != prepare_seed(seed):
            QMessageBox.warning(None, _('Error'), _('Incorrect seed'), _('OK'))
            return False
        else:
            return True


    def get_seed_text(self, seed_e):
        text = unicode(seed_e.toPlainText()).strip()
        text = ' '.join(text.split())
        return text

    def is_any(self, text):
        return Wallet.is_seed(text) or Wallet.is_old_mpk(text) or Wallet.is_xpub(text) or Wallet.is_xprv(text) or Wallet.is_address(text) or Wallet.is_private_key(text)

    def is_mpk(self, text):
        return Wallet.is_xpub(text) or Wallet.is_old_mpk(text)

    def enter_seed_dialog(self, msg, sid, func=None):
        if func is None:
            func = self.is_any
        vbox, seed_e = seed_dialog.enter_seed_box(msg, self, sid)
        vbox.addStretch(1)
        button = OkButton(self, _('Next'))
        vbox.addLayout(Buttons(CancelButton(self), button))
        button.setEnabled(False)
        seed_e.textChanged.connect(lambda: button.setEnabled(func(self.get_seed_text(seed_e))))
        self.set_layout(vbox)
        if not self.exec_():
            return
        return self.get_seed_text(seed_e)


    def multi_mpk_dialog(self, xpub_hot, n):
        vbox = QVBoxLayout()
        vbox0 = seed_dialog.show_seed_box(MSG_SHOW_MPK, xpub_hot, 'hot')
        vbox.addLayout(vbox0)
        entries = []
        for i in range(n):
            vbox2, seed_e2 = seed_dialog.enter_seed_box(MSG_ENTER_COLD_MPK, self, 'cold')
            vbox.addLayout(vbox2)
            entries.append(seed_e2)
        vbox.addStretch(1)
        button = OkButton(self, _('Next'))
        vbox.addLayout(Buttons(CancelButton(self), button))
        button.setEnabled(False)
        f = lambda: button.setEnabled( map(lambda e: Wallet.is_xpub(self.get_seed_text(e)), entries) == [True]*len(entries))
        for e in entries:
            e.textChanged.connect(f)
        self.set_layout(vbox)
        if not self.exec_():
            return
        return map(lambda e: self.get_seed_text(e), entries)


    def multi_seed_dialog(self, n):
        vbox = QVBoxLayout()
        vbox1, seed_e1 = seed_dialog.enter_seed_box(MSG_ENTER_SEED_OR_MPK, self, 'hot')
        vbox.addLayout(vbox1)
        entries = [seed_e1]
        for i in range(n):
            vbox2, seed_e2 = seed_dialog.enter_seed_box(MSG_ENTER_SEED_OR_MPK, self, 'cold')
            vbox.addLayout(vbox2)
            entries.append(seed_e2)
        vbox.addStretch(1)
        button = OkButton(self, _('Next'))
        vbox.addLayout(Buttons(CancelButton(self), button))
        button.setEnabled(False)
        f = lambda: button.setEnabled( map(lambda e: self.is_any(self.get_seed_text(e)), entries) == [True]*len(entries))
        for e in entries:
            e.textChanged.connect(f)
        self.set_layout(vbox)
        if not self.exec_():
            return
        return map(lambda e: self.get_seed_text(e), entries)


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
        # skip this if config already exists
        if self.config.get('server') is not None:
            return

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
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _('Next'))))

        self.set_layout(vbox)
        if not self.exec_():
            return

        if b2.isChecked():
            return NetworkDialog(self.network, self.config, None).do_exec()
        else:
            self.config.set_key('auto_cycle', True, True)
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
        vbox.addLayout(Buttons(CloseButton(self)))
        if not self.exec_():
            return None


    def choice(self, title, msg, choices):
        vbox = QVBoxLayout()
        self.set_layout(vbox)
        vbox.addWidget(QLabel(title))
        gb2 = QGroupBox(msg)
        vbox.addWidget(gb2)
        group2 = QButtonGroup()
        for i,c in enumerate(choices):
            button = QRadioButton(gb2)
            button.setText(c[1])
            vbox.addWidget(button)
            group2.addButton(button)
            group2.setId(button, i)
            if i==0:
                button.setChecked(True)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _('Next'))))
        if not self.exec_():
            return
        wallet_type = choices[group2.checkedId()][0]
        return wallet_type


    def question(self, msg, yes_label=_('OK'), no_label=_('Cancel'), icon=None):
        vbox = QVBoxLayout()
        self.set_layout(vbox)
        if icon:
            logo = QLabel()
            logo.setPixmap(icon)
            vbox.addWidget(logo)
        label = QLabel(msg)
        label.setWordWrap(True)
        vbox.addWidget(label)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self, no_label), OkButton(self, yes_label)))
        if not self.exec_():
            return None
        return True


    def show_seed(self, seed, sid):
        vbox = seed_dialog.show_seed_box_msg(seed, sid)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _("Next"))))
        self.set_layout(vbox)
        return self.exec_()


    def password_dialog(self):
        msg = _("Please choose a password to encrypt your wallet keys.")+'\n'\
              +_("Leave these fields empty if you want to disable encryption.")
        from password_dialog import make_password_dialog, run_password_dialog
        self.set_layout( make_password_dialog(self, None, msg) )
        return run_password_dialog(self, None, self)[2]





    def run(self, action):

        if action == 'new':
            action, wallet_type = self.restore_or_create()
            if wallet_type == 'multisig':
                wallet_type = self.choice(_("Multi Signature Wallet"), 'Select wallet type', [('2of2', _("2 of 2")),('2of3',_("2 of 3"))])
                if not wallet_type:
                    return
            elif wallet_type == 'hardware':
                hardware_wallets = map(lambda x:(x[1],x[2]), filter(lambda x:x[0]=='hardware', electrum.wallet.wallet_types))
                wallet_type = self.choice(_("Hardware Wallet"), 'Select your hardware wallet', hardware_wallets)
                if not wallet_type:
                    return
            elif wallet_type == 'twofactor':
                wallet_type = '2fa'

            if action == 'create':
                self.storage.put('wallet_type', wallet_type, False)

        if action is None:
            return

        if action == 'restore':
            wallet = self.restore(wallet_type)
            if not wallet:
                return
            action = None
        else:
            wallet = Wallet(self.storage)
            action = wallet.get_action()
            # fixme: password is only needed for multiple accounts
            password = None

        while action is not None:
            util.print_error("installwizard:", wallet, action)

            if action == 'create_seed':
                seed = wallet.make_seed()
                if not self.show_seed(seed, None):
                    return
                if not self.verify_seed(seed, None):
                    return
                password = self.password_dialog()
                wallet.add_seed(seed, password)
                wallet.create_master_keys(password)

            elif action == 'add_cosigner':
                xpub1 = wallet.master_public_keys.get("x1/")
                r = self.multi_mpk_dialog(xpub1, 1)
                if not r:
                    return
                xpub2 = r[0]
                wallet.add_master_public_key("x2/", xpub2)

            elif action == 'add_two_cosigners':
                xpub1 = wallet.master_public_keys.get("x1/")
                r = self.multi_mpk_dialog(xpub1, 2)
                if not r:
                    return
                xpub2, xpub3 = r
                wallet.add_master_public_key("x2/", xpub2)
                wallet.add_master_public_key("x3/", xpub3)

            elif action == 'create_accounts':
                wallet.create_main_account(password)
                self.waiting_dialog(wallet.synchronize)

            else:
                f = run_hook('get_wizard_action', self, wallet, action)
                if not f:
                    raise BaseException('unknown wizard action', action)
                r = f(wallet, self)
                if not r:
                    return

            # next action
            action = wallet.get_action()


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
                msg = _("Recovery successful") if wallet.is_found() else _("No transactions found for this seed")
            else:
                msg = _("This wallet was restored offline. It may contain more addresses than displayed.")
            QMessageBox.information(None, _('Information'), msg, _('OK'))

        return wallet



    def restore(self, t):

            if t == 'standard':
                text = self.enter_seed_dialog(MSG_ENTER_ANYTHING, None)
                if not text:
                    return
                if Wallet.is_xprv(text):
                    password = self.password_dialog()
                    wallet = Wallet.from_xprv(text, password, self.storage)
                elif Wallet.is_old_mpk(text):
                    wallet = Wallet.from_old_mpk(text, self.storage)
                elif Wallet.is_xpub(text):
                    wallet = Wallet.from_xpub(text, self.storage)
                elif Wallet.is_address(text):
                    wallet = Wallet.from_address(text, self.storage)
                elif Wallet.is_private_key(text):
                    password = self.password_dialog()
                    wallet = Wallet.from_private_key(text, password, self.storage)
                elif Wallet.is_seed(text):
                    password = self.password_dialog()
                    wallet = Wallet.from_seed(text, self.storage)
                    wallet.add_seed(text, password)
                    wallet.create_master_keys(password)
                    wallet.create_main_account(password)
                else:
                    raise BaseException('unknown wallet type')

            elif t in ['2of2']:
                r = self.multi_seed_dialog(1)
                if not r:
                    return
                text1, text2 = r
                wallet = Wallet_2of2(self.storage)
                if (Wallet.is_seed(text1) or Wallet.is_seed(text2) or
                    Wallet.is_xprv(text1) or Wallet.is_xprv(text2)):
                    password = self.password_dialog()
                else:
                    password = None

                if (Wallet.is_seed(text2) or Wallet.is_xprv(text2)) and Wallet.is_xpub(text1):
                    c = text1
                    text1 = text2
                    text2 = c

                if Wallet.is_seed(text1):
                    wallet.add_seed(text1, password)
                    wallet.create_master_keys(password)
                elif Wallet.is_xprv(text1):
                    xpub = bitcoin.xpub_from_xprv(text1)
                    wallet.add_master_public_key(wallet.root_name, xpub)
                    wallet.add_master_private_key(wallet.root_name, text1, password)
                else:
                    wallet.add_master_public_key("x1/", text1)

                if Wallet.is_seed(text2):
                    wallet.add_cosigner_seed(text2, "x2/", password)
                elif Wallet.is_xpub(text2):
                    wallet.add_master_public_key("x2/", text2)

                wallet.create_main_account(password)


            elif t in ['2of3']:
                r = self.multi_seed_dialog(2)
                if not r:
                    return
                text1, text2, text3 = r
                wallet = Wallet_2of3(self.storage)
                if (Wallet.is_seed(text1) or Wallet.is_seed(text2) or Wallet.is_seed(text3) or
                    Wallet.is_xprv(text1) or Wallet.is_xprv(text2) or Wallet.is_xprv(text3)):
                    password = self.password_dialog()
                else:
                    password = None

                if Wallet.is_xpub(text1) and (Wallet.is_seed(text2) or Wallet.is_xprv(text2)):
                    temp = text1
                    text1 = text2
                    text2 = temp

                if Wallet.is_xpub(text1) and (Wallet.is_seed(text3) or Wallet.is_xprv(text3)):
                    temp = text1
                    text1 = text3
                    text3 = temp

                if Wallet.is_seed(text1):
                    wallet.add_seed(text1, password)
                    wallet.create_master_keys(password)
                elif Wallet.is_xprv(text1):
                    xpub = bitcoin.xpub_from_xprv(text1)
                    wallet.add_master_public_key(wallet.root_name, xpub)
                    wallet.add_master_private_key(wallet.root_name, text1, password)
                else:
                    wallet.add_master_public_key("x1/", text1)

                if Wallet.is_seed(text2):
                    wallet.add_cosigner_seed(text2, "x2/", password)
                elif Wallet.is_xprv(text2):
                    xpub = bitcoin.xpub_from_xprv(text2)
                    wallet.add_master_public_key(wallet.root_name, xpub)
                    wallet.add_master_private_key(wallet.root_name, text2, password)
                elif Wallet.is_xpub(text2):
                    wallet.add_master_public_key("x2/", text2)

                if Wallet.is_seed(text3):
                    wallet.add_cosigner_seed(text3, "x3/", password)
                elif Wallet.is_xprv(text3):
                    xpub = bitcoin.xpub_from_xprv(text3)
                    wallet.add_master_public_key(wallet.root_name, xpub)
                    wallet.add_master_private_key(wallet.root_name, text3, password)
                elif Wallet.is_xpub(text3):
                    wallet.add_master_public_key("x3/", text3)

                wallet.create_main_account(password)

            else:
                self.storage.put('wallet_type', t)
                wallet = run_hook('installwizard_restore', self, self.storage)
                if not wallet:
                    return

            # create first keys offline
            self.waiting_dialog(wallet.synchronize)

            return wallet
