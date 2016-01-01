from sys import stdout

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

import electrum
from electrum.i18n import _

import seed_dialog
from network_dialog import NetworkDialog
from util import *
from password_dialog import PasswordDialog

from electrum.wallet import Wallet
from electrum.mnemonic import prepare_seed
from electrum.wizard import (WizardBase, UserCancelled,
                             MSG_ENTER_PASSWORD, MSG_RESTORE_PASSPHRASE,
                             MSG_COSIGNER, MSG_ENTER_SEED_OR_MPK,
                             MSG_SHOW_MPK, MSG_VERIFY_SEED)

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



class InstallWizard(WindowModalDialog, MessageBoxMixin, WizardBase):

    def __init__(self, config, app, plugins):
        title = 'Electrum  -  ' + _('Install Wizard')
        WindowModalDialog.__init__(self, None, title=title)
        self.app = app
        self.config = config
        # Set for base base class
        self.plugins = plugins
        self.language_for_seed = config.get('language')
        self.setMinimumSize(575, 400)
        self.setMaximumSize(575, 400)
        self.connect(self, QtCore.SIGNAL('accept'), self.accept)
        self.stack = QStackedLayout()
        self.setLayout(self.stack)

    def open_wallet(self, *args):
        '''Wrap the base wizard implementation with try/except blocks
        to give a sensible error message to the user.'''
        wallet = None
        try:
            wallet = super(InstallWizard, self).open_wallet(*args)
        except UserCancelled:
            self.print_error("wallet creation cancelled by user")
        except Exception as e:
            traceback.print_exc(file=stdout)
            self.show_error(str(e))
        return wallet

    def remove_from_recently_open(self, filename):
        self.config.remove_from_recently_open(filename)

    # Called by plugins
    def confirm(self, msg, icon=None):
        '''Returns True or False'''
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
        vbox.addLayout(Buttons(CancelButton(self, _("Cancel")),
                               OkButton(self, _("Next"))))
        if not self.exec_():
            raise UserCancelled

    def show_and_verify_seed(self, seed, is_valid=None):
        """Show the user their seed.  Ask them to re-enter it.  Return
        True on success."""
        self.show_seed(seed)
        self.app.clipboard().clear()
        self.verify_seed(seed, is_valid)

    def pw_dialog(self, msg, kind):
        dialog = PasswordDialog(self, None, msg, kind)
        accepted, p, pass_text = dialog.run()
        if not accepted:
            raise UserCancelled
        return pass_text

    def request_passphrase(self, device_text, restore=True):
        """Request a passphrase for a wallet from the given device and
        confirm it.  restore is True if restoring a wallet.  Should return
        a unicode string."""
        if restore:
            msg = MSG_RESTORE_PASSPHRASE % device_text
        return unicode(self.pw_dialog(msg, PasswordDialog.PW_PASSPHRASE) or '')

    def request_password(self, msg=None):
        """Request the user enter a new password and confirm it.  Return
        the password or None for no password."""
        return self.pw_dialog(msg or MSG_ENTER_PASSWORD, PasswordDialog.PW_NEW)

    def query_hardware(self, choices, action):
        if action == 'create':
            msg = _('Select the hardware wallet to create')
        else:
            msg = _('Select the hardware wallet to restore')
        return self.choice(msg, choices)

    def choose_server(self, network):
        # Show network dialog if config does not exist
        if self.config.get('server') is None:
            self.network_dialog(network)

    def set_layout(self, layout):
        w = QWidget()
        w.setLayout(layout)
        self.stack.addWidget(w)
        self.stack.setCurrentWidget(w)
        self.show()

    def query_create_or_restore(self, wallet_kinds):
        """Ask the user what they want to do, and to what wallet kind.
        wallet_kinds is an array of tuples (kind, description).
        Return a tuple (action, kind).  Action is 'create' or 'restore',
        and kind is one of the wallet kinds passed."""
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

        for i, (wtype,name) in enumerate(wallet_kinds):
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
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _('Next'))))
        self.set_layout(vbox)
        self.show()
        self.raise_()

        if not self.exec_():
            raise UserCancelled

        action = 'create' if b1.isChecked() else 'restore'
        wallet_type = wallet_kinds[group2.checkedId()][0]
        return action, wallet_type

    def verify_seed(self, seed, is_valid=None):
        while True:
            r = self.request_seed(MSG_VERIFY_SEED, is_valid)
            if prepare_seed(r) == prepare_seed(seed):
                return
            self.show_error(_('Incorrect seed'))

    def get_seed_text(self, seed_e):
        text = unicode(seed_e.toPlainText()).strip()
        text = ' '.join(text.split())
        return text

    def request_seed(self, msg, is_valid=None):
        is_valid = is_valid or Wallet.is_any
        vbox, seed_e = seed_dialog.enter_seed_box(msg, self)
        vbox.addStretch(1)
        button = OkButton(self, _('Next'))
        vbox.addLayout(Buttons(CancelButton(self), button))
        button.setEnabled(False)
        def set_enabled():
            button.setEnabled(is_valid(self.get_seed_text(seed_e)))
        seed_e.textChanged.connect(set_enabled)
        self.set_layout(vbox)
        if not self.exec_():
            raise UserCancelled
        return self.get_seed_text(seed_e)

    def request_many(self, n, xpub_hot=None):
        vbox = QVBoxLayout()
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        vbox.addWidget(scroll)

        w = QWidget()
        scroll.setWidget(w)

        innerVbox = QVBoxLayout()
        w.setLayout(innerVbox)

        entries = []
        if xpub_hot:
            vbox0 = seed_dialog.show_seed_box(MSG_SHOW_MPK, xpub_hot, 'hot')
        else:
            vbox0, seed_e1 = seed_dialog.enter_seed_box(MSG_ENTER_SEED_OR_MPK, self, 'hot')
            entries.append(seed_e1)
        innerVbox.addLayout(vbox0)

        for i in range(n):
            if xpub_hot:
                msg = MSG_COSIGNER % (i + 1)
            else:
                msg = MSG_ENTER_SEED_OR_MPK
            vbox2, seed_e2 = seed_dialog.enter_seed_box(msg, self, 'cold')
            innerVbox.addLayout(vbox2)
            entries.append(seed_e2)

        vbox.addStretch(1)
        button = OkButton(self, _('Next'))
        vbox.addLayout(Buttons(CancelButton(self), button))
        button.setEnabled(False)
        def get_texts():
            return [self.get_seed_text(entry) for entry in entries]
        def set_enabled():
            texts = get_texts()
            is_valid = Wallet.is_xpub if xpub_hot else Wallet.is_any
            all_valid = all(is_valid(text) for text in texts)
            if xpub_hot:
                texts.append(xpub_hot)
            has_dups = len(set(texts)) < len(texts)
            button.setEnabled(all_valid and not has_dups)
        for e in entries:
            e.textChanged.connect(set_enabled)
        self.set_layout(vbox)
        if not self.exec_():
            raise UserCancelled
        return get_texts()

    def network_dialog(self, network):
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
            NetworkDialog(network, self.config, None).do_exec()
        else:
            self.config.set_key('auto_connect', True, True)
            network.auto_connect = True

    def choice(self, msg, choices):
        vbox = QVBoxLayout()
        self.set_layout(vbox)
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
        next_button = OkButton(self, _('Next'))
        next_button.setEnabled(bool(choices))
        vbox.addLayout(Buttons(CancelButton(self), next_button))
        if not self.exec_():
            raise UserCancelled
        wallet_type = choices[group2.checkedId()][0]
        return wallet_type

    def query_multisig(self, action):
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
            raise UserCancelled
        m = int(m_edit.value())
        n = int(n_edit.value())
        wallet_type = '%dof%d'%(m,n)
        return wallet_type

    def show_seed(self, seed):
        vbox = seed_dialog.show_seed_box_msg(seed, None)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self, _("Next"))))
        self.set_layout(vbox)
        if not self.exec_():
            raise UserCancelled
