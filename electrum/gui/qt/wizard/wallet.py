import os

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, Qt, QTimer
from PyQt5.QtWidgets import QApplication, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget, QFileDialog

from electrum.daemon import Daemon
from electrum.i18n import _
from electrum.storage import StorageReadWriteError
from electrum.util import WalletFileException, get_new_wallet_name
from electrum.wallet import wallet_types
from .wizard import QEAbstractWizard, WizardComponent
from electrum.logging import get_logger
from electrum import WalletStorage, mnemonic
from electrum.wizard import NewWalletWizard
from ..password_dialog import PasswordLayout, PW_NEW, MSG_ENTER_PASSWORD
from ..seed_dialog import SeedLayout, MSG_PASSPHRASE_WARN_ISSUE4566
from ..util import ChoicesLayout, PasswordLineEdit, char_width_in_lineedit, WWLabel


class QENewWalletWizard(NewWalletWizard, QEAbstractWizard):
    _logger = get_logger(__name__)

    # createError = pyqtSignal([str], arguments=["error"])
    # createSuccess = pyqtSignal()

    def __init__(self, config: 'SimpleConfig', app: QApplication, daemon: Daemon, path, parent=None):
        NewWalletWizard.__init__(self, daemon)
        QEAbstractWizard.__init__(self, config, app, parent)
        self._daemon = daemon
        self._path = path

        # attach view names and accept handlers
        self.navmap_merge({
            'wallet_name': { 'gui': WCWalletName },
            'wallet_type': { 'gui': WCWalletType },
            'keystore_type': { 'gui': WCKeystoreType },
            'create_seed': { 'gui': WCCreateSeed },
            'create_ext': { 'gui': WCCreateExt },
            'confirm_seed': { 'gui': WCConfirmSeed },
            'confirm_ext': { 'gui': WCConfirmExt },
            'have_seed': { 'gui': 'WCHaveSeed' },
            'bip39_refine': { 'gui': 'WCBIP39Refine' },
            'have_master_key': { 'gui': 'WCHaveMasterKey' },
            'multisig': { 'gui': 'WCMultisig' },
            'multisig_cosigner_keystore': { 'gui': 'WCCosignerKeystore' },
            'multisig_cosigner_key': { 'gui': 'WCHaveMasterKey' },
            'multisig_cosigner_seed': { 'gui': 'WCHaveSeed' },
            'multisig_cosigner_bip39_refine': { 'gui': 'WCBIP39Refine' },
            'imported': { 'gui': 'WCImport' },
            'wallet_password': { 'gui': 'WCWalletPassword' }
        })

        # insert seed extension entry/confirm as separate views
        self.navmap_merge({
            'create_seed': {
                'next': lambda d: 'create_ext' if d['seed_extend'] else 'confirm_seed'
            },
            'create_ext': {
                'next': 'confirm_seed',
            },
            'confirm_seed': {
                'next': lambda d: 'confirm_ext' if d['seed_extend'] else self.on_have_or_confirm_seed(d),
                'accept': lambda d: None if d['seed_extend'] else self.maybe_master_pubkey(d),
            },
            'confirm_ext': {
                'next': self.on_have_or_confirm_seed,
                'accept': self.maybe_master_pubkey,
            }
        })

    # pathChanged = pyqtSignal()
    # @pyqtProperty(str, notify=pathChanged)
    # def path(self):
    #     return self._path
    #
    # @path.setter
    # def path(self, path):
    #     self._path = path
    #     self.pathChanged.emit()
    #
    def is_single_password(self):
        # TODO: also take into account if possible with existing set of wallets. see qedaemon.py
        return self._daemon.config.WALLET_USE_SINGLE_PASSWORD

    # @pyqtSlot('QJSValue', result=bool)
    # def hasDuplicateMasterKeys(self, js_data):
    #     self._logger.info('Checking for duplicate masterkeys')
    #     data = js_data.toVariant()
    #     return self.has_duplicate_masterkeys(data)
    #
    # @pyqtSlot('QJSValue', result=bool)
    # def hasHeterogeneousMasterKeys(self, js_data):
    #     self._logger.info('Checking for heterogeneous masterkeys')
    #     data = js_data.toVariant()
    #     return self.has_heterogeneous_masterkeys(data)
    #
    # @pyqtSlot(str, str, result=bool)
    # def isMatchingSeed(self, seed, seed_again):
    #     return mnemonic.is_matching_seed(seed=seed, seed_again=seed_again)
    #
    # @pyqtSlot('QJSValue', bool, str)
    # def createStorage(self, js_data, single_password_enabled, single_password):
    #     self._logger.info('Creating wallet from wizard data')
    #     data = js_data.toVariant()
    #
    #     if single_password_enabled and single_password:
    #         data['encrypt'] = True
    #         data['password'] = single_password
    #
    #     path = os.path.join(os.path.dirname(self._daemon.daemon.config.get_wallet_path()), data['wallet_name'])
    #
    #     try:
    #         self.create_storage(path, data)
    #
    #         # minimally populate self after create
    #         self._password = data['password']
    #         self.path = path
    #
    #         self.createSuccess.emit()
    #     except Exception as e:
    #         self._logger.error(f"createStorage errored: {e!r}")
    #         self.createError.emit(str(e))


class WCWalletName(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Electrum wallet'))

        path = wizard._path

        if os.path.isdir(path):
            raise Exception("wallet path cannot point to a directory")

        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('Wallet') + ':'))
        self.name_e = QLineEdit()
        hbox.addWidget(self.name_e)
        button = QPushButton(_('Choose...'))
        hbox.addWidget(button)
        self.layout().addLayout(hbox)

        msg_label = WWLabel('')
        self.layout().addWidget(msg_label)
        hbox2 = QHBoxLayout()
        pw_e = PasswordLineEdit('', self)
        pw_e.setFixedWidth(17 * char_width_in_lineedit())
        pw_label = QLabel(_('Password') + ':')
        hbox2.addWidget(pw_label)
        hbox2.addWidget(pw_e)
        hbox2.addStretch()
        self.layout().addLayout(hbox2)

        self.layout().addSpacing(50)
        vbox_create_new = QVBoxLayout()
        vbox_create_new.addWidget(QLabel(_('Alternatively') + ':'), alignment=Qt.AlignLeft)
        button_create_new = QPushButton(_('Create New Wallet'))
        button_create_new.setMinimumWidth(120)
        vbox_create_new.addWidget(button_create_new, alignment=Qt.AlignLeft)
        widget_create_new = QWidget()
        widget_create_new.setLayout(vbox_create_new)
        vbox_create_new.setContentsMargins(0, 0, 0, 0)
        self.layout().addWidget(widget_create_new)

        temp_storage = None  # type: Optional[WalletStorage]
        wallet_folder = os.path.dirname(path)

        def on_choose():
            path, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
            if path:
                self.name_e.setText(path)

        def on_filename(filename):
            # FIXME? "filename" might contain ".." (etc) and hence sketchy path traversals are possible
            nonlocal temp_storage
            temp_storage = None
            msg = None
            if filename:
                path = os.path.join(wallet_folder, filename)
                # wallet_from_memory = get_wallet_from_daemon(path)
                wallet_from_memory = self.wizard._daemon.get_wallet(path)
                try:
                    if wallet_from_memory:
                        temp_storage = wallet_from_memory.storage  # type: Optional[WalletStorage]
                    else:
                        temp_storage = WalletStorage(path)
                except (StorageReadWriteError, WalletFileException) as e:
                    msg = _('Cannot read file') + f'\n{repr(e)}'
                except Exception as e:
                    self.logger.exception('')
                    msg = _('Cannot read file') + f'\n{repr(e)}'
            else:
                msg = ""
            # self.next_button.setEnabled(temp_storage is not None)
            self.valid = temp_storage is not None
            user_needs_to_enter_password = False
            if temp_storage:
                if not temp_storage.file_exists():
                    msg =_("This file does not exist.") + '\n' \
                          + _("Press 'Next' to create this wallet, or choose another file.")
                elif not wallet_from_memory:
                    if temp_storage.is_encrypted_with_user_pw():
                        msg = _("This file is encrypted with a password.") + '\n' \
                              + _('Enter your password or choose another file.')
                        user_needs_to_enter_password = True
                    elif temp_storage.is_encrypted_with_hw_device():
                        msg = _("This file is encrypted using a hardware device.") + '\n' \
                              + _("Press 'Next' to choose device to decrypt.")
                    else:
                        msg = _("Press 'Next' to open this wallet.")
                else:
                    msg = _("This file is already open in memory.") + "\n" \
                        + _("Press 'Next' to create/focus window.")
            if msg is None:
                msg = _('Cannot read file')
            msg_label.setText(msg)
            widget_create_new.setVisible(bool(temp_storage and temp_storage.file_exists()))
            if user_needs_to_enter_password:
                pw_label.show()
                pw_e.show()
                pw_e.setFocus()
            else:
                pw_label.hide()
                pw_e.hide()

        button.clicked.connect(on_choose)
        button_create_new.clicked.connect(
            lambda: self.name_e.setText(get_new_wallet_name(wallet_folder)))  # FIXME get_new_wallet_name might raise
        self.name_e.textChanged.connect(on_filename)
        self.name_e.setText(os.path.basename(path))

    def apply(self):
        self.wizard_data['wallet_name'] = self.name_e.text()


class WCWalletType(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Create new wallet'))
        message = _('What kind of wallet do you want to create?')
        wallet_kinds = [
            ('standard',  _('Standard wallet')),
            ('2fa',       _('Wallet with two-factor authentication')),
            ('multisig',  _('Multi-signature wallet')),
            ('imported',  _('Import Bitcoin addresses or private keys')),
        ]
        choices = [pair for pair in wallet_kinds if pair[0] in wallet_types]

        self.c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        self.clayout = ChoicesLayout(message, c_titles)
        self.layout().addLayout(self.clayout.layout())
        self._valid = True

    def apply(self):
        self.wizard_data['wallet_type'] = self.c_values[self.clayout.selected_index()]


class WCKeystoreType(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Keystore'))
        message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
        choices = [
            ('createseed', _('Create a new seed')),
            ('haveseed',   _('I already have a seed')),
            ('masterkey',  _('Use a master key')),
            ('hardware',   _('Use a hardware device'))
        ]

        self.c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        self.clayout = ChoicesLayout(message, c_titles)
        self.layout().addLayout(self.clayout.layout())
        self._valid = True

    def apply(self):
        self.wizard_data['keystore_type'] = self.c_values[self.clayout.selected_index()]


class WCCreateSeed(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Wallet Seed'))
        self._busy = True
        self.seed_type = 'standard' if self.wizard.config.WIZARD_DONT_CREATE_SEGWIT else 'segwit'
        self.slayout = None
        self.seed = None
        QTimer.singleShot(100, self.create_seed)

    def apply(self):
        if self.slayout:
            self.wizard_data['seed'] = self.seed
            self.wizard_data['seed_type'] = self.seed_type
            self.wizard_data['seed_extend'] = self.slayout.is_ext
            self.wizard_data['seed_variant'] = 'electrum'

    def create_seed(self):
        self.busy = True
        self.seed = mnemonic.Mnemonic('en').make_seed(seed_type=self.seed_type)

        self.slayout = SeedLayout(
            title=_('Your wallet generation seed is:'),
            seed=self.seed,
            options=['ext'],
            msg=True,
            parent=self,
            config=self.wizard.config,
        )
        self.layout().addLayout(self.slayout)
        self.busy = False
        self.valid = True


class WCConfirmSeed(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Confirm Seed'))
        message = ' '.join([
            _('Your seed is important!'),
            _('If you lose your seed, your money will be permanently lost.'),
            _('To make sure that you have properly saved your seed, please retype it here.')
        ])

        self.layout().addWidget(QLabel(message))

        self._valid = True

    def apply(self):
        pass


class WCCreateExt(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Seed Extension'))

        message = '\n'.join([
            _('You may extend your seed with custom words.'),
            _('Your seed extension must be saved together with your seed.'),
        ])
        warning = '\n'.join([
            _('Note that this is NOT your encryption password.'),
            _('If you do not know what this is, leave this field empty.'),
        ])

        self.ext_edit = SeedExtensionEdit(self, message=message, warning=warning)
        self.ext_edit.textEdited.connect(self.on_text_edited)
        self.layout().addWidget(self.ext_edit)

    def on_text_edited(self, text):
        self.ext_edit.warn_issue4566 = self.wizard_data['keystore_type'] == 'haveseed' and \
                                       self.wizard_data['seed_type'] == 'bip39'
        self.valid = len(text) > 0

    def apply(self):
        self.wizard_data['seed_extra_words'] = self.ext_edit.text()


class WCConfirmExt(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Confirm Seed Extension'))
        message = '\n'.join([
            _('Your seed extension must be saved together with your seed.'),
            _('Please type it here.'),
        ])
        self.ext_edit = SeedExtensionEdit(self, message=message)
        self.ext_edit.textEdited.connect(self.on_text_edited)
        self.layout().addWidget(self.ext_edit)

    def on_text_edited(self, text):
        self.valid = text == self.wizard_data['seed_extra_words']

    def apply(self):
        pass


class SeedExtensionEdit(QWidget):
    def __init__(self, parent, *, message: str = None, warning: str = None, warn_issue4566: bool = False):
        super().__init__(parent)

        self.warn_issue4566 = warn_issue4566

        layout = QVBoxLayout()
        self.setLayout(layout)

        if message:
            layout.addWidget(WWLabel(message))

        self.line = QLineEdit()
        layout.addWidget(self.line)

        def f(text):
            if self.warn_issue4566:
                text_whitespace_normalised = ' '.join(text.split())
                warn_issue4566_label.setVisible(text != text_whitespace_normalised)
        self.line.textEdited.connect(f)

        if warning:
            layout.addWidget(WWLabel(warning))

        warn_issue4566_label = WWLabel(MSG_PASSPHRASE_WARN_ISSUE4566)
        warn_issue4566_label.setVisible(False)
        layout.addWidget(warn_issue4566_label)

        # expose textEdited signal and text() func to widget
        self.textEdited = self.line.textEdited
        self.text = self.line.text
