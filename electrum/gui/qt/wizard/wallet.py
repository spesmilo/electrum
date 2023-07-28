import os

from PyQt5.QtCore import Qt, QTimer, QRect
from PyQt5.QtGui import QPen, QPainter, QPalette
from PyQt5.QtWidgets import (QApplication, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget,
                             QFileDialog, QSlider, QGridLayout)

from electrum.bip32 import is_bip32_derivation, BIP32Node
from electrum.daemon import Daemon
from electrum.i18n import _
from electrum.keystore import bip44_derivation, bip39_to_seed
from electrum.storage import StorageReadWriteError
from electrum.util import WalletFileException, get_new_wallet_name
from electrum.wallet import wallet_types
from .wizard import QEAbstractWizard, WizardComponent
from electrum.logging import get_logger
from electrum import WalletStorage, mnemonic, keystore
from electrum.wizard import NewWalletWizard
from ..bip39_recovery_dialog import Bip39RecoveryDialog
from ..password_dialog import PasswordLayout, PW_NEW, MSG_ENTER_PASSWORD
from ..seed_dialog import SeedLayout, MSG_PASSPHRASE_WARN_ISSUE4566, KeysLayout
from ..util import ChoicesLayout, PasswordLineEdit, char_width_in_lineedit, WWLabel, InfoButton, font_height

WIF_HELP_TEXT = (_('WIF keys are typed in Electrum, based on script type.') + '\n\n' +
                 _('A few examples') + ':\n' +
                 'p2pkh:KxZcY47uGp9a...       \t-> 1DckmggQM...\n' +
                 'p2wpkh-p2sh:KxZcY47uGp9a... \t-> 3NhNeZQXF...\n' +
                 'p2wpkh:KxZcY47uGp9a...      \t-> bc1q3fjfk...')


class QENewWalletWizard(NewWalletWizard, QEAbstractWizard):
    _logger = get_logger(__name__)

    # createError = pyqtSignal([str], arguments=["error"])
    # createSuccess = pyqtSignal()

    def __init__(self, config: 'SimpleConfig', app: QApplication, daemon: Daemon, path, parent=None):
        NewWalletWizard.__init__(self, daemon)
        QEAbstractWizard.__init__(self, config, app, parent)
        self._daemon = daemon
        self._path = path

        # attach gui classes to views
        self.navmap_merge({
            'wallet_name': { 'gui': WCWalletName },
            'wallet_type': { 'gui': WCWalletType },
            'keystore_type': { 'gui': WCKeystoreType },
            'create_seed': { 'gui': WCCreateSeed },
            'create_ext': { 'gui': WCCreateExt },
            'confirm_seed': { 'gui': WCConfirmSeed },
            'confirm_ext': { 'gui': WCConfirmExt },
            'have_seed': { 'gui': WCHaveSeed },
            'bip39_refine': { 'gui': WCBIP39Refine },
            'have_master_key': { 'gui': 'WCHaveMasterKey' },
            'multisig': { 'gui': WCMultisig },
            'multisig_cosigner_keystore': { 'gui': 'WCCosignerKeystore' },
            'multisig_cosigner_key': { 'gui': 'WCHaveMasterKey' },
            'multisig_cosigner_seed': { 'gui': 'WCHaveSeed' },
            'multisig_cosigner_bip39_refine': { 'gui': 'WCBIP39Refine' },
            'imported': { 'gui': WCImport },
            'wallet_password': { 'gui': WCWalletPassword }
        })

        # modify default flow, insert seed extension entry/confirm as separate views
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

    def create_storage(self, single_password: str = None):
        self._logger.info('Creating wallet from wizard data')
        # data = js_data.toVariant()
        data = self._current.wizard_data

        if self.is_single_password() and single_password:
            data['encrypt'] = True
            data['password'] = single_password

        path = os.path.join(os.path.dirname(self._daemon.config.get_wallet_path()), data['wallet_name'])

        try:
            super().create_storage(path, data)

            # minimally populate self after create
            self._password = data['password']
            # self.path = path

            # self.createSuccess.emit()
            return True
        except Exception as e:
            self._logger.error(f"createStorage errored: {e!r}")
            return False
            # self.createError.emit(str(e))


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

    def on_ready(self):
        QTimer.singleShot(1, self.create_seed)

    def apply(self):
        if self.slayout:
            self.wizard_data['seed'] = self.seed
            self.wizard_data['seed_type'] = self.seed_type
            self.wizard_data['seed_extend'] = self.slayout.is_ext
            self.wizard_data['seed_variant'] = 'electrum'
            self.wizard_data['seed_extra_words'] = ''  # empty default

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

        self.layout().addWidget(WWLabel(message))

        # TODO: SeedLayout assumes too much in parent, refactor SeedLayout
        # for now, fake parent.next_button.setEnabled
        class Hack:
            def setEnabled(self2, b):
                self.valid = b
        self.next_button = Hack()

        self.slayout = SeedLayout(
            is_seed=lambda x: x == self.wizard_data['seed'],
            parent=self,
            config=self.wizard.config,
        )
        self.layout().addLayout(self.slayout)

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
        self.layout().addStretch(1)

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
        self.layout().addStretch(1)

    def on_text_edited(self, text):
        self.valid = text == self.wizard_data['seed_extra_words']

    def apply(self):
        pass


class WCHaveSeed(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Enter Seed'))
        self.layout().addWidget(WWLabel(_('Please enter your seed phrase in order to restore your wallet.')))

        # TODO: SeedLayout assumes too much in parent, refactor SeedLayout
        # for now, fake parent.next_button.setEnabled
        class Hack:
            def setEnabled(self2, b):
                self.valid = b
        self.next_button = Hack()

    def on_ready(self):
        options = ['ext'] if self.wizard_data['wallet_type'] == '2fa' else ['ext', 'bip39', 'slip39']
        self.slayout = SeedLayout(
            is_seed=self.is_seed,
            options=options,
            parent=self,
            config=self.wizard.config,
        )
        self.layout().addLayout(self.slayout)

    def is_seed(self, x):
        if self.wizard_data['wallet_type'] == 'standard':
            return mnemonic.is_seed(x)
        else:
            return mnemonic.seed_type(x) in ['standard', 'segwit']

    def apply(self):
        self.wizard_data['seed'] = self.slayout.get_seed()
        self.wizard_data['seed_variant'] = self.slayout.seed_type
        if self.slayout.seed_type == 'electrum':
            self.wizard_data['seed_type'] = mnemonic.seed_type(self.slayout.get_seed())
        else:
            self.wizard_data['seed_type'] = self.slayout.seed_type
        self.wizard_data['seed_extend'] = self.slayout.is_ext
        self.wizard_data['seed_extra_words'] = ''  # empty default


class WCBIP39Refine(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Script type and Derivation path'))

    def on_ready(self):
        if self.wizard_data['wallet_type'] == 'multisig':
            raise Exception('NYI')

        message1 = _('Choose the type of addresses in your wallet.')
        message2 = ' '.join([
            _('You can override the suggested derivation path.'),
            _('If you are not sure what this is, leave this field unchanged.')
        ])
        hide_choices = False

        default_choice_idx = 2
        choices = [
            ('standard', 'legacy (p2pkh)', bip44_derivation(0, bip43_purpose=44)),
            ('p2wpkh-p2sh', 'p2sh-segwit (p2wpkh-p2sh)', bip44_derivation(0, bip43_purpose=49)),
            ('p2wpkh', 'native segwit (p2wpkh)', bip44_derivation(0, bip43_purpose=84)),
        ]

        passphrase = self.wizard_data['seed_extra_words'] if self.wizard_data['seed_extend'] else ''
        root_seed = bip39_to_seed(self.wizard_data['seed'], passphrase)

        def get_account_xpub(account_path):
            root_node = BIP32Node.from_rootseed(root_seed, xtype="standard")
            account_node = root_node.subkey_at_private_derivation(account_path)
            account_xpub = account_node.to_xpub()
            return account_xpub

        if get_account_xpub:
            button = QPushButton(_("Detect Existing Accounts"))

            def on_account_select(account):
                script_type = account["script_type"]
                if script_type == "p2pkh":
                    script_type = "standard"
                button_index = self.c_values.index(script_type)
                button = self.clayout.group.buttons()[button_index]
                button.setChecked(True)
                self.derivation_path_edit.setText(account["derivation_path"])

            button.clicked.connect(lambda: Bip39RecoveryDialog(self, get_account_xpub, on_account_select))
            self.layout().addWidget(button, alignment=Qt.AlignLeft)
            self.layout().addWidget(QLabel(_("Or")))

        self.c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        c_default_text = [x[2] for x in choices]

        def on_choice_click(clayout):
            idx = clayout.selected_index()
            self.derivation_path_edit.setText(c_default_text[idx])
        self.clayout = ChoicesLayout(message1, c_titles, on_choice_click,
                                     checked_index=default_choice_idx)
        if not hide_choices:
            self.layout().addLayout(self.clayout.layout())

        self.layout().addWidget(WWLabel(message2))

        self.derivation_path_edit = QLineEdit()
        self.derivation_path_edit.textChanged.connect(self.validate)
        on_choice_click(self.clayout)  # set default value for derivation path
        self.layout().addWidget(self.derivation_path_edit)

    def validate(self):
        self.valid = is_bip32_derivation(self.derivation_path_edit.text())

    def apply(self):
        self.wizard_data['script_type'] = self.c_values[self.clayout.selected_index()]
        self.wizard_data['derivation_path'] = str(self.derivation_path_edit.text())


class WCMultisig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Multi-Signature Wallet'))

        def on_m(m):
            m_label.setText(_('Require {0} signatures').format(m))
            cw.set_m(m)
            backup_warning_label.setVisible(cw.m != cw.n)

        def on_n(n):
            n_label.setText(_('From {0} cosigners').format(n))
            cw.set_n(n)
            m_edit.setMaximum(n)
            backup_warning_label.setVisible(cw.m != cw.n)

        backup_warning_label = WWLabel(_('Warning: to be able to restore a multisig wallet, '
                                         'you should include the master public key for each cosigner '
                                         'in all of your backups.'))

        cw = CosignWidget(2, 2)
        m_label = QLabel()
        n_label = QLabel()

        m_edit = QSlider(Qt.Horizontal, self)
        m_edit.setMinimum(1)
        m_edit.setMaximum(2)
        m_edit.setValue(2)
        m_edit.valueChanged.connect(on_m)
        on_m(m_edit.value())

        n_edit = QSlider(Qt.Horizontal, self)
        n_edit.setMinimum(2)
        n_edit.setMaximum(15)
        n_edit.setValue(2)
        n_edit.valueChanged.connect(on_n)
        on_n(n_edit.value())

        grid = QGridLayout()
        grid.addWidget(n_label, 0, 0)
        grid.addWidget(n_edit, 0, 1)
        grid.addWidget(m_label, 1, 0)
        grid.addWidget(m_edit, 1, 1)

        self.layout().addWidget(cw)
        self.layout().addWidget(WWLabel(_('Choose the number of signatures needed to unlock funds in your wallet:')))
        self.layout().addLayout(grid)
        self.layout().addSpacing(2 * char_width_in_lineedit())
        self.layout().addWidget(backup_warning_label)

        self.n_edit = n_edit
        self.m_edit = m_edit

        self._valid = True

    def apply(self):
        self.wizard_data['multisig_participants'] = int(self.n_edit.value())
        self.wizard_data['multisig_signatures'] = int(self.m_edit.value())
        self.wizard_data['multisig_cosigner_data'] = {}


class WCImport(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Import Bitcoin Addresses'))
        message = _(
            'Enter a list of Bitcoin addresses (this will create a watching-only wallet), or a list of private keys.')
        # self.add_xpub_dialog(title=title, message=message, run_next=self.on_import,
        #                      is_valid=v, allow_multi=True, show_wif_help=True)
        header_layout = QHBoxLayout()
        label = WWLabel(message)
        label.setMinimumWidth(400)
        header_layout.addWidget(label)
        header_layout.addWidget(InfoButton(WIF_HELP_TEXT), alignment=Qt.AlignRight)

        # TODO: KeysLayout assumes too much in parent, refactor KeysLayout
        # for now, fake parent.next_button.setEnabled
        class Hack:
            def setEnabled(self2, b):
                self.valid = b
            def setToolTip(self2, b):
                pass
        self.next_button = Hack()

        v = lambda x: keystore.is_address_list(x) or keystore.is_private_key_list(x, raise_on_error=True)
        self.slayout = KeysLayout(parent=self, header_layout=header_layout, is_valid=v,
                                  allow_multi=True, config=self.wizard.config)
        self.layout().addLayout(self.slayout)

    def apply(self):
        text = self.slayout.get_text()
        if keystore.is_address_list(text):
            self.wizard_data['address_list'] = text
        elif keystore.is_private_key_list(text):
            self.wizard_data['private_key_list'] = text


class WCWalletPassword(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Wallet Password'))

        # TODO: PasswordLayout assumes a button, refactor PasswordLayout
        # for now, fake next_button.setEnabled
        class Hack:
            def setEnabled(self2, b):
                self.valid = b
        self.next_button = Hack()

        self.pw_layout = PasswordLayout(
            msg=MSG_ENTER_PASSWORD,
            kind=PW_NEW,
            OK_button=self.next_button,
            # force_disable_encrypt_cb=force_disable_encrypt_cb
        )
        self.pw_layout.encrypt_cb.setChecked(True)
        self.layout().addLayout(self.pw_layout.layout())
        self.layout().addStretch(1)

    def apply(self):
        self.wizard_data['password'] = self.pw_layout.new_password()
        self.wizard_data['encrypt'] = self.pw_layout.encrypt_cb.isChecked()


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


class CosignWidget(QWidget):
    def __init__(self, m, n):
        QWidget.__init__(self)
        self.size = max(120, 9 * font_height())
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
        bgcolor = self.palette().color(QPalette.Background)
        pen = QPen(bgcolor, 7, Qt.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.Antialiasing)
        qp.setBrush(Qt.gray)
        for i in range(self.n):
            alpha = int(16 * 360 * i/self.n)
            alpha2 = int(16 * 360 * 1/self.n)
            qp.setBrush(Qt.green if i < self.m else Qt.gray)
            qp.drawPie(self.R, alpha, alpha2)
        qp.end()
