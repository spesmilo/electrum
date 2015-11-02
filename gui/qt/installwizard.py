import re
import sys
import threading

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

import electrum
from electrum.i18n import _
from electrum import Wallet
from electrum import bitcoin
from electrum import util

import seed_dialog
from network_dialog import NetworkDialog
from util import *

from electrum.plugins import always_hook, run_hook
from electrum.mnemonic import prepare_seed

MSG_ENTER_ANYTHING    = _("Please enter a seed phrase, a master key, a list of Bitcoin addresses, or a list of private keys")
MSG_SHOW_MPK          = _("Here is your master public key")
MSG_ENTER_MPK         = _("Please enter your master public key")
MSG_ENTER_SEED_OR_MPK = _("Please enter a seed phrase or a master key (xpub or xprv)")
MSG_VERIFY_SEED       = _("Your seed is important!") + "\n" + _("To make sure that you have properly saved your seed, please retype it here.")


class CosignWidget(QWidget):
    size = 120

    def __init__(self, m, n):
        QWidget.__init__(self)
        self.R = QRect(0, 0, self.size, self.size)
        self.setGeometry(self.R)
        self.m = m
        self.n = n

    def set_n(self, n):
        self.n = n
        self.update()

    def set_m(self, m):
        self.m = m
        self.update()

    def paintEvent(self, event):
        import math
        bgcolor = self.palette().color(QPalette.Background)
        pen = QPen(bgcolor, 7, QtCore.Qt.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.Antialiasing)
        qp.setBrush(Qt.gray)
        for i in range(self.n):
            alpha = int(16* 360 * i/self.n)
            alpha2 = int(16* 360 * 1/self.n)
            qp.setBrush(Qt.green if i<self.m else Qt.gray)
            qp.drawPie(self.R, alpha, alpha2)
        qp.end()



class InstallWizard(QDialog):

    def __init__(self, app, config, network, storage):
        QDialog.__init__(self)
        self.app = app
        self.config = config
        self.network = network
        self.storage = storage
        self.setMinimumSize(575, 400)
        self.setMaximumSize(575, 400)
        self.setWindowTitle('Electrum' + '  -  ' + _('Install Wizard'))
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
        vbox1 = QVBoxLayout()
        gb1.setLayout(vbox1)

        b1 = QRadioButton(gb1)
        b1.setText(_("Create new wallet"))
        b1.setChecked(True)

        b2 = QRadioButton(gb1)
        b2.setText(_("Restore a wallet or import keys"))

        group1 = QButtonGroup()
        group1.addButton(b1)
        group1.addButton(b2)
        vbox1.addWidget(b1)
        vbox1.addWidget(b2)

        gb2 = QGroupBox(_("Wallet type:"))
        vbox.addWidget(gb2)

        vbox2 = QVBoxLayout()
        gb2.setLayout(vbox2)

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
            vbox2.addWidget(button)
            group2.addButton(button)
            group2.setId(button, i)

            if i==0:
                button.setChecked(True)

        vbox.addStretch(1)
        self.set_layout(vbox)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _('Next'))))
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
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        vbox.addWidget(scroll)

        w = QWidget()
        scroll.setWidget(w)

        innerVbox = QVBoxLayout()
        w.setLayout(innerVbox)

        vbox0 = seed_dialog.show_seed_box(MSG_SHOW_MPK, xpub_hot, 'hot')
        innerVbox.addLayout(vbox0)
        entries = []
        for i in range(n):
            msg = _("Please enter the master public key of cosigner") + ' %d'%(i+1)
            vbox2, seed_e2 = seed_dialog.enter_seed_box(msg, self, 'cold')
            innerVbox.addLayout(vbox2)
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
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        vbox.addWidget(scroll)

        w = QWidget()
        scroll.setWidget(w)

        innerVbox = QVBoxLayout()
        w.setLayout(innerVbox)

        vbox1, seed_e1 = seed_dialog.enter_seed_box(MSG_ENTER_SEED_OR_MPK, self, 'hot')
        innerVbox.addLayout(vbox1)
        entries = [seed_e1]
        for i in range(n):
            vbox2, seed_e2 = seed_dialog.enter_seed_box(MSG_ENTER_SEED_OR_MPK, self, 'cold')
            innerVbox.addLayout(vbox2)
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
        grid.addWidget(b1,1,0)
        grid.addWidget(b2,2,0)
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
            self.config.set_key('auto_connect', True, True)
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

        vbox2 = QVBoxLayout()
        gb2.setLayout(vbox2)

        group2 = QButtonGroup()
        for i,c in enumerate(choices):
            button = QRadioButton(gb2)
            button.setText(c[1])
            vbox2.addWidget(button)
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


    def multisig_choice(self):

        vbox = QVBoxLayout()
        self.set_layout(vbox)
        vbox.addWidget(QLabel(_("Multi Signature Wallet")))

        cw = CosignWidget(2, 2)
        vbox.addWidget(cw, 1)
        vbox.addWidget(QLabel(_("Please choose the number of signatures needed to unlock funds in your wallet") + ':'))

        m_edit = QSpinBox()
        n_edit = QSpinBox()
        m_edit.setValue(2)
        n_edit.setValue(2)
        n_edit.setMinimum(2)
        n_edit.setMaximum(15)
        m_edit.setMinimum(1)
        m_edit.setMaximum(2)
        n_edit.valueChanged.connect(m_edit.setMaximum)

        n_edit.valueChanged.connect(cw.set_n)
        m_edit.valueChanged.connect(cw.set_m)

        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('Require')))
        hbox.addWidget(m_edit)
        hbox.addWidget(QLabel(_('of')))
        hbox.addWidget(n_edit)
        hbox.addWidget(QLabel(_('signatures')))
        hbox.addStretch(1)

        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _('Next'))))
        if not self.exec_():
            return
        m = int(m_edit.value())
        n = int(n_edit.value())
        wallet_type = '%dof%d'%(m,n)
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
        if self.storage.file_exists and action != 'new':
            path = self.storage.path
            msg = _("The file '%s' contains an incompletely created wallet.\n"
                    "Do you want to complete its creation now?") % path
            if not question(msg):
                if question(_("Do you want to delete '%s'?") % path):
                    os.remove(path)
                    QMessageBox.information(self, _('Warning'),
                                            _('The file was removed'), _('OK'))
                    return
                return
        self.show()
        if action == 'new':
            action, wallet_type = self.restore_or_create()
        else:
            wallet_type = None
        try:
            wallet = self.run_wallet_type(action, wallet_type)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            QMessageBox.information(None, _('Error'), str(e), _('OK'))
            return
        return wallet

    def run_wallet_type(self, action, wallet_type):
        if action in ['create', 'restore']:
            if wallet_type == 'multisig':
                wallet_type = self.multisig_choice()
                if not wallet_type:
                    return
            elif wallet_type == 'hardware':
                hardware_wallets = []
                for item in electrum.wallet.wallet_types:
                    t, name, description, loader = item
                    if t == 'hardware':
                        try:
                            p = loader()
                        except:
                            util.print_error("cannot load plugin for:", name)
                            continue
                        if p:
                            hardware_wallets.append((name, description))
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

        # load wallet in plugins
        always_hook('installwizard_load_wallet', wallet, self)

        while action is not None:
            util.print_error("installwizard:", wallet, action)

            if action == 'create_seed':
                lang = self.config.get('language')
                seed = wallet.make_seed(lang)
                if not self.show_seed(seed, None):
                    return
                self.app.clipboard().clear()
                if not self.verify_seed(seed, None):
                    return
                password = self.password_dialog()
                wallet.add_seed(seed, password)
                wallet.create_master_keys(password)

            elif action == 'add_cosigners':
                n = int(re.match('(\d+)of(\d+)', wallet.wallet_type).group(2))
                xpub1 = wallet.master_public_keys.get("x1/")
                r = self.multi_mpk_dialog(xpub1, n - 1)
                if not r:
                    return
                for i, xpub in enumerate(r):
                    wallet.add_master_public_key("x%d/"%(i+2), xpub)

            elif action == 'create_accounts':
                wallet.create_main_account(password)
                self.waiting_dialog(wallet.synchronize)

            else:
                f = always_hook('get_wizard_action', self, wallet, action)
                if not f:
                    raise BaseException('unknown wizard action', action)
                r = f(wallet, self)
                if not r:
                    return

            # next action
            action = wallet.get_action()


        if self.network:
            # show network dialog if config does not exist
            if self.config.get('server') is None:
                self.network_dialog()
        else:
            QMessageBox.information(None, _('Warning'), _('You are offline'), _('OK'))


        # start wallet threads
        wallet.start_threads(self.network)

        if action == 'restore':
            self.waiting_dialog(lambda: wallet.wait_until_synchronized(self.waiting_label.setText))
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
            password = self.password_dialog() if Wallet.is_seed(text) or Wallet.is_xprv(text) or Wallet.is_private_key(text) else None
            wallet = Wallet.from_text(text, password, self.storage)
        elif re.match('(\d+)of(\d+)', t):
            n = int(re.match('(\d+)of(\d+)', t).group(2))
            key_list = self.multi_seed_dialog(n - 1)
            if not key_list:
                return
            password = self.password_dialog() if any(map(lambda x: Wallet.is_seed(x) or Wallet.is_xprv(x), key_list)) else None
            wallet = Wallet.from_multisig(key_list, password, self.storage, t)
        else:
            self.storage.put('wallet_type', t, False)
            # call the constructor to load the plugin (side effect)
            Wallet(self.storage)
            wallet = always_hook('installwizard_restore', self, self.storage)
            if not wallet:
                util.print_error("no wallet")
                return
        # create first keys offline
        self.waiting_dialog(wallet.synchronize)
        return wallet
