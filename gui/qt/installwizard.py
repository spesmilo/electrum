import sys

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

import electrum
from electrum.i18n import _

from seed_dialog import SeedDisplayLayout, SeedWarningLayout, SeedInputLayout
from network_dialog import NetworkChoiceLayout
from util import *
from password_dialog import PasswordLayout, PW_NEW, PW_PASSPHRASE

from electrum.wallet import Wallet
from electrum.mnemonic import prepare_seed
from electrum.util import UserCancelled
from electrum.wizard import (WizardBase,
                             MSG_ENTER_PASSWORD, MSG_RESTORE_PASSPHRASE,
                             MSG_COSIGNER, MSG_ENTER_SEED_OR_MPK,
                             MSG_SHOW_MPK, MSG_VERIFY_SEED,
                             MSG_GENERATING_WAIT)

def clean_text(seed_e):
    text = unicode(seed_e.toPlainText()).strip()
    text = ' '.join(text.split())
    return text

class CosignWidget(QWidget):
    size = 120

    def __init__(self, m, n):
        QWidget.__init__(self)
        self.R = QRect(0, 0, self.size, self.size)
        self.setGeometry(self.R)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)
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


# WindowModalDialog must come first as it overrides show_error
class InstallWizard(QDialog, MessageBoxMixin, WizardBase):

    def __init__(self, config, app, plugins):
        QDialog.__init__(self, None)
        self.setWindowTitle('Electrum  -  ' + _('Install Wizard'))
        self.app = app
        self.config = config
        # Set for base base class
        self.plugins = plugins
        self.language_for_seed = config.get('language')
        self.setMinimumSize(530, 370)
        self.setMaximumSize(530, 370)
        self.connect(self, QtCore.SIGNAL('accept'), self.accept)
        self.title = WWLabel()
        self.main_widget = QWidget()
        self.cancel_button = QPushButton(_("Cancel"), self)
        self.next_button = QPushButton(_("Next"), self)
        self.next_button.setDefault(True)
        self.logo = QLabel()
        self.please_wait = QLabel(_("Please wait..."))
        self.please_wait.setAlignment(Qt.AlignCenter)
        self.icon_filename = None
        self.loop = QEventLoop()
        self.rejected.connect(lambda: self.loop.exit(False))
        self.cancel_button.clicked.connect(lambda: self.loop.exit(False))
        self.next_button.clicked.connect(lambda: self.loop.exit(True))
        outer_vbox = QVBoxLayout(self)
        inner_vbox = QVBoxLayout()
        inner_vbox = QVBoxLayout()
        inner_vbox.addWidget(self.title)
        inner_vbox.addWidget(self.main_widget)
        inner_vbox.addStretch(1)
        inner_vbox.addWidget(self.please_wait)
        inner_vbox.addStretch(1)
        icon_vbox = QVBoxLayout()
        icon_vbox.addWidget(self.logo)
        icon_vbox.addStretch(1)
        hbox = QHBoxLayout()
        hbox.addLayout(icon_vbox)
        hbox.addSpacing(5)
        hbox.addLayout(inner_vbox)
        hbox.setStretchFactor(inner_vbox, 1)
        outer_vbox.addLayout(hbox)
        outer_vbox.addLayout(Buttons(self.cancel_button, self.next_button))
        self.set_icon(':icons/electrum.png')
        self.show()
        self.raise_()
        self.refresh_gui()  # Need for QT on MacOSX.  Lame.

    def finished(self):
        '''Ensure the dialog is closed.'''
        self.accept()
        self.refresh_gui()

    def on_error(self, exc_info):
        if not isinstance(exc_info[1], UserCancelled):
            traceback.print_exception(*exc_info)
            self.show_error(str(exc_info[1]))

    def set_icon(self, filename):
        prior_filename, self.icon_filename = self.icon_filename, filename
        self.logo.setPixmap(QPixmap(filename).scaledToWidth(60))
        return prior_filename

    def set_main_layout(self, layout, title=None, raise_on_cancel=True,
                        next_enabled=True):
        self.title.setText(title or "")
        self.title.setVisible(bool(title))
        # Get rid of any prior layout by assigning it to a temporary widget
        prior_layout = self.main_widget.layout()
        if prior_layout:
            QWidget().setLayout(prior_layout)
        self.main_widget.setLayout(layout)
        self.cancel_button.setEnabled(True)
        self.next_button.setEnabled(next_enabled)
        self.main_widget.setVisible(True)
        self.please_wait.setVisible(False)
        result = self.loop.exec_()
        if not result and raise_on_cancel:
            raise UserCancelled
        self.title.setVisible(False)
        self.cancel_button.setEnabled(False)
        self.next_button.setEnabled(False)
        self.main_widget.setVisible(False)
        self.please_wait.setVisible(True)
        self.refresh_gui()
        return result

    def refresh_gui(self):
        # For some reason, to refresh the GUI this needs to be called twice
        self.app.processEvents()
        self.app.processEvents()

    def run(self, *args):
        '''Wrap the base wizard implementation with try/except blocks
        to give a sensible error message to the user.'''
        wallet = None
        try:
            wallet = WizardBase.run(self, *args)
        except UserCancelled:
            self.print_error("wallet creation cancelled by user")
            self.accept()  # For when called from menu
        except BaseException as e:
            self.on_error(sys.exc_info())
            raise
        return wallet

    def remove_from_recently_open(self, filename):
        self.config.remove_from_recently_open(filename)

    def request_seed(self, title, is_valid=None):
        is_valid = is_valid or Wallet.is_any
        slayout = SeedInputLayout()
        def sanitized_seed():
            return clean_text(slayout.seed_edit())
        def set_enabled():
            self.next_button.setEnabled(is_valid(sanitized_seed()))
        slayout.seed_edit().textChanged.connect(set_enabled)
        self.set_main_layout(slayout.layout(), title, next_enabled=False)
        return sanitized_seed()

    def show_seed(self, seed):
        slayout = SeedWarningLayout(seed)
        self.set_main_layout(slayout.layout())

    def verify_seed(self, seed, is_valid=None):
        while True:
            r = self.request_seed(MSG_VERIFY_SEED, is_valid)
            if prepare_seed(r) == prepare_seed(seed):
                return
            self.show_error(_('Incorrect seed'))

    def show_and_verify_seed(self, seed, is_valid=None):
        """Show the user their seed.  Ask them to re-enter it.  Return
        True on success."""
        self.show_seed(seed)
        self.app.clipboard().clear()
        self.verify_seed(seed, is_valid)

    def pw_layout(self, msg, kind):
        playout = PasswordLayout(None, msg, kind, self.next_button)
        self.set_main_layout(playout.layout())
        return playout.new_password()

    def request_passphrase(self, device_text, restore=True):
        """Request a passphrase for a wallet from the given device and
        confirm it.  restore is True if restoring a wallet.  Should return
        a unicode string."""
        if restore:
            msg = MSG_RESTORE_PASSPHRASE % device_text
        return unicode(self.pw_layout(msg, PW_PASSPHRASE) or '')

    def request_password(self, msg=None):
        """Request the user enter a new password and confirm it.  Return
        the password or None for no password."""
        return self.pw_layout(msg or MSG_ENTER_PASSWORD, PW_NEW)

    def show_restore(self, wallet, network):
        # FIXME: these messages are shown after the install wizard is
        # finished and the window closed.  On MacOSX they appear parented
        # with a re-appeared ghost install wizard window...
        if network:
            def task():
                wallet.wait_until_synchronized()
                if wallet.is_found():
                    msg = _("Recovery successful")
                else:
                    msg = _("No transactions found for this seed")
                self.emit(QtCore.SIGNAL('synchronized'), msg)
            self.connect(self, QtCore.SIGNAL('synchronized'), self.show_message)
            t = threading.Thread(target = task)
            t.daemon = True
            t.start()
        else:
            msg = _("This wallet was restored offline. It may "
                    "contain more addresses than displayed.")
            self.show_message(msg)

    def create_addresses(self, wallet):
        def task():
            wallet.synchronize()
            self.emit(QtCore.SIGNAL('accept'))
        t = threading.Thread(target = task)
        t.start()
        self.please_wait.setText(MSG_GENERATING_WAIT)
        self.refresh_gui()

    def query_create_or_restore(self, wallet_kinds):
        """Ask the user what they want to do, and which wallet kind.
        wallet_kinds is an array of translated wallet descriptions.
        Return a a tuple (action, kind_index).  Action is 'create' or
        'restore', and kind the index of the wallet kind chosen."""

        actions = [_("Create a new wallet"),
                   _("Restore a wallet or import keys")]
        title = _("Electrum could not find an existing wallet.")
        actions_clayout = ChoicesLayout(_("What do you want to do?"), actions)
        wallet_clayout = ChoicesLayout(_("Wallet kind:"), wallet_kinds)

        vbox = QVBoxLayout()
        vbox.addLayout(actions_clayout.layout())
        vbox.addLayout(wallet_clayout.layout())
        self.set_main_layout(vbox, title)

        action = ['create', 'restore'][actions_clayout.selected_index()]
        return action, wallet_clayout.selected_index()

    def query_hw_wallet_choice(self, msg, action, choices):
        actions = [_("Initialize a new or wiped device"),
                   _("Use a device you have already set up"),
                   _("Restore Electrum wallet from device seed words")]
        default_action = 1 if action == 'create' else 2
        actions_clayout = ChoicesLayout(_("What do you want to do?"), actions,
                                        checked_index=default_action)
        wallet_clayout = ChoicesLayout(msg, choices)

        vbox = QVBoxLayout()
        vbox.addLayout(actions_clayout.layout())
        vbox.addLayout(wallet_clayout.layout())
        self.set_main_layout(vbox)
        self.next_button.setEnabled(len(choices) != 0)

        if actions_clayout.selected_index() == 2:
            action = 'restore'
        else:
            action = 'create'
        return action, wallet_clayout.selected_index()

    def request_many(self, n, xpub_hot=None):
        vbox = QVBoxLayout()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        vbox.addWidget(scroll)

        w = QWidget()
        innerVbox = QVBoxLayout(w)
        scroll.setWidget(w)

        entries = []

        if xpub_hot:
            layout = SeedDisplayLayout(xpub_hot, title=MSG_SHOW_MPK, sid='hot')
        else:
            layout = SeedInputLayout(title=MSG_ENTER_SEED_OR_MPK, sid='hot')
            entries.append(layout.seed_edit())
        innerVbox.addLayout(layout.layout())

        for i in range(n):
            msg = MSG_COSIGNER % (i + 1) if xpub_hot else MSG_ENTER_SEED_OR_MPK
            layout = SeedInputLayout(title=msg, sid='cold')
            innerVbox.addLayout(layout.layout())
            entries.append(layout.seed_edit())

        def get_texts():
            return [clean_text(entry) for entry in entries]
        def set_enabled():
            texts = get_texts()
            is_valid = Wallet.is_xpub if xpub_hot else Wallet.is_any
            all_valid = all(is_valid(text) for text in texts)
            if xpub_hot:
                texts.append(xpub_hot)
            has_dups = len(set(texts)) < len(texts)
            self.next_button.setEnabled(all_valid and not has_dups)
        for e in entries:
            e.textChanged.connect(set_enabled)
        self.set_main_layout(vbox, next_enabled=False)
        return get_texts()

    def choose_server(self, network):
        title = _("Electrum communicates with remote servers to get "
                  "information about your transactions and addresses. The "
                  "servers all fulfil the same purpose only differing in "
                  "hardware. In most cases you simply want to let Electrum "
                  "pick one at random.  However if you prefer feel free to "
                  "select a server manually.")
        choices = [_("Auto connect"), _("Select server manually")]
        choices_title = _("How do you want to connect to a server? ")
        clayout = ChoicesLayout(choices_title, choices)
        self.set_main_layout(clayout.layout(), title)

        auto_connect = True
        if clayout.selected_index() == 1:
            nlayout = NetworkChoiceLayout(network, self.config, wizard=True)
            if self.set_main_layout(nlayout.layout(), raise_on_cancel=False):
                nlayout.accept()
                auto_connect = False
        self.config.set_key('auto_connect', auto_connect, True)
        network.auto_connect = auto_connect

    def query_choice(self, msg, choices):
        clayout = ChoicesLayout(msg, choices)
        self.set_main_layout(clayout.layout(), next_enabled=bool(choices))
        return clayout.selected_index()

    def query_multisig(self, action):
        cw = CosignWidget(2, 2)
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

        vbox = QVBoxLayout()
        vbox.addWidget(cw)
        vbox.addWidget(WWLabel(_("Choose the number of signatures needed "
                          "to unlock funds in your wallet:")))
        vbox.addLayout(hbox)
        self.set_main_layout(vbox, _("Multi-Signature Wallet"))
        m = int(m_edit.value())
        n = int(n_edit.value())
        wallet_type = '%dof%d'%(m,n)
        return wallet_type
