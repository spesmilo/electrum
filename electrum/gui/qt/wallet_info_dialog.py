# Copyright (C) 2023 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import os
from typing import TYPE_CHECKING
from functools import partial

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QLabel, QVBoxLayout, QGridLayout,
    QHBoxLayout, QPushButton, QWidget, QTabWidget)

from electrum.plugin import run_hook
from electrum.i18n import _
from electrum.wallet import Multisig_Wallet

from .main_window import protected
from electrum.gui.qt.wizard.wallet import QEKeystoreWizard
from .qrtextedit import ShowQRTextEdit
from .util import (
    read_QIcon, WindowModalDialog, Buttons,
    WWLabel, CloseButton, HelpButton, font_height, ShowQRLineEdit
)

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class WalletInfoDialog(WindowModalDialog):

    def __init__(self, parent: QWidget, *, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, parent, _("Wallet Information"))
        self.setMinimumSize(800, 100)
        self.window = window
        self.wallet = wallet = window.wallet
        # required for @protected decorator
        self._protected_requires_password = lambda: self.wallet.has_keystore_encryption() or self.wallet.storage.is_encrypted_with_user_pw()
        config = window.config
        vbox = QVBoxLayout()
        wallet_type = wallet.db.get('wallet_type', '')
        if wallet.is_watching_only():
            wallet_type += ' [{}]'.format(_('watching-only'))
        seed_available = _('False')
        if wallet.has_seed():
            seed_available = _('True')
            seed_available += f" ({wallet.get_seed_type()})"
        keystore_types = [k.get_type_text() for k in wallet.get_keystores()]
        grid = QGridLayout()
        basename = os.path.basename(wallet.storage.path)
        cur_row = 0
        grid.addWidget(WWLabel(_("Wallet name")+ ':'), cur_row, 0)
        grid.addWidget(WWLabel(basename), cur_row, 1)
        cur_row += 1
        if db_metadata := wallet.db.get_db_metadata():
            grid.addWidget(WWLabel(_("File created") + ':'), cur_row, 0)
            grid.addWidget(WWLabel(db_metadata.to_str()), cur_row, 1)
            cur_row += 1
        grid.addWidget(WWLabel(_("Wallet type")+ ':'), cur_row, 0)
        grid.addWidget(WWLabel(wallet_type), cur_row, 1)
        cur_row += 1
        grid.addWidget(WWLabel(_("Script type")+ ':'), cur_row, 0)
        grid.addWidget(WWLabel(wallet.txin_type), cur_row, 1)
        cur_row += 1
        grid.addWidget(WWLabel(_("Seed available") + ':'), cur_row, 0)
        grid.addWidget(WWLabel(str(seed_available)), cur_row, 1)
        cur_row += 1
        if len(keystore_types) <= 1:
            grid.addWidget(WWLabel(_("Keystore type") + ':'), cur_row, 0)
            ks_type = str(keystore_types[0]) if keystore_types else _('No keystore')
            grid.addWidget(WWLabel(ks_type), cur_row, 1)
            cur_row += 1
        # lightning
        grid.addWidget(WWLabel(_('Lightning') + ':'), cur_row, 0)
        from .util import IconLabel
        if wallet.has_lightning():
            if wallet.lnworker.has_deterministic_node_id():
                grid.addWidget(WWLabel(_('Enabled')), cur_row, 1)
            else:
                label = IconLabel(text='Enabled, non-recoverable channels')
                label.setIcon(read_QIcon('cloud_no'))
                grid.addWidget(label, cur_row, 1)
                if wallet.get_seed_type() == 'segwit':
                    msg = _("Your channels cannot be recovered from seed, because they were created with an old version of Electrum. "
                            "This means that you must save a backup of your wallet every time you create a new channel.\n\n"
                            "If you want this wallet to have recoverable channels, you must close your existing channels and restore this wallet from seed")
                else:
                    msg = _("Your channels cannot be recovered from seed. "
                            "This means that you must save a backup of your wallet every time you create a new channel.\n\n"
                            "If you want to have recoverable channels, you must create a new wallet with an Electrum seed")
                grid.addWidget(HelpButton(msg), cur_row, 3)
            cur_row += 1
            grid.addWidget(WWLabel(_('Lightning Node ID:')), cur_row, 0)
            cur_row += 1
            nodeid_text = wallet.lnworker.node_keypair.pubkey.hex()
            nodeid_e = ShowQRLineEdit(nodeid_text, config, title=_("Node ID"))
            grid.addWidget(nodeid_e, cur_row, 0, 1, 4)
            cur_row += 1
        else:
            if wallet.can_have_lightning():
                grid.addWidget(WWLabel('Not enabled'), cur_row, 1)
                button = QPushButton(_("Enable"))
                button.pressed.connect(lambda: window.init_lightning_dialog(self))
                grid.addWidget(button, cur_row, 3)
            else:
                grid.addWidget(WWLabel(_("Not available for this wallet.")), cur_row, 1)
                grid.addWidget(HelpButton(_("Lightning is currently restricted to HD wallets with p2wpkh addresses.")), cur_row, 2)
            cur_row += 1
        vbox.addLayout(grid)

        labels_clayout = None

        if wallet.is_deterministic():
            keystores = wallet.get_keystores()

            self.keystore_tabs = QTabWidget()

            for idx, ks in enumerate(keystores):
                ks_w = QWidget()
                ks_vbox = QVBoxLayout()
                ks_w.setLayout(ks_vbox)

                status_label = _('This keystore is watching-only (disabled)') if ks.is_watching_only() else _('This keystore is active (enabled)')
                ks_vbox.addWidget(QLabel(status_label))
                label = f'{ks.label}' if hasattr(ks, 'label') and ks.label else ''
                ks_vbox.addWidget(QLabel(_('Type') + ': ' + f'{ks.get_type_text()}' + ' ' + label))

                mpk_text = ShowQRTextEdit(ks.get_master_public_key(), config=config)
                mpk_text.setMaximumHeight(max(150, 10 * font_height()))
                mpk_text.addCopyButton()
                run_hook('show_xpub_button', mpk_text, ks)
                ks_vbox.addWidget(WWLabel(_("Master Public Key")))
                ks_vbox.addWidget(mpk_text)

                der_path_hbox = QHBoxLayout()
                der_path_hbox.setContentsMargins(0, 0, 0, 0)
                der_path_hbox.addWidget(WWLabel(_("Derivation path") + ':'))
                der_path_text = WWLabel(ks.get_derivation_prefix() or _("unknown"))
                der_path_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                der_path_hbox.addWidget(der_path_text)
                der_path_hbox.addStretch()
                ks_vbox.addLayout(der_path_hbox)

                bip32fp_hbox = QHBoxLayout()
                bip32fp_hbox.setContentsMargins(0, 0, 0, 0)
                bip32fp_hbox.addWidget(QLabel("BIP32 root fingerprint:"))
                bip32fp_text = WWLabel(ks.get_root_fingerprint() or _("unknown"))
                bip32fp_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                bip32fp_hbox.addWidget(bip32fp_text)
                bip32fp_hbox.addStretch()
                ks_vbox.addLayout(bip32fp_hbox)
                ks_buttons = []
                if not ks.is_watching_only():
                    rm_keystore_button = QPushButton('Disable keystore')
                    rm_keystore_button.clicked.connect(partial(self.disable_keystore, ks))
                    ks_buttons.insert(0, rm_keystore_button)
                else:
                    add_keystore_button = QPushButton('Enable Keystore')
                    add_keystore_button.clicked.connect(self.enable_keystore)
                    ks_buttons.insert(0, add_keystore_button)
                ks_vbox.addLayout(Buttons(*ks_buttons))
                tab_label = _("Cosigner") + f' {idx+1}' if len(keystores) > 1 else _("Keystore")
                index = self.keystore_tabs.addTab(ks_w, tab_label)
                if not ks.is_watching_only():
                    self.keystore_tabs.setTabIcon(index, read_QIcon('confirmed.svg'))
            vbox.addWidget(self.keystore_tabs)

        vbox.addStretch(1)

        buttons = [CloseButton(self)]
        btn_export_info = run_hook('wallet_info_buttons', window, self)
        if btn_export_info is None:
            btn_export_info = []
        buttons = btn_export_info + buttons

        btns = Buttons(*buttons)
        vbox.addLayout(btns)
        self.setLayout(vbox)

    def disable_keystore(self, keystore):
        if self.wallet.has_channels():
            self.window.show_message(_('Cannot disable keystore: You have active lightning channels'))
            return

        msg = _('Disable keystore? This will make the keytore watching-only.')
        if self.wallet.storage.is_encrypted_with_hw_device():
            msg += '\n\n' + _('Note that this will disable wallet file encryption, because it uses your hardware wallet device.')
        if not self.window.question(msg):
            return
        self.accept()
        self.wallet.disable_keystore(keystore)
        self.window.gui_object.reload_windows()

    def enable_keystore(self, b: bool):
        dialog = QEKeystoreWizard(self.window.config, self.window.wallet.wallet_type, self.window.gui_object.app, self.window.gui_object.plugins)
        result = dialog.run()
        if not result:
            return
        keystore, is_hardware = result
        for k in self.wallet.get_keystores():
            if k.get_master_public_key() == keystore.get_master_public_key():
                break
        else:
            self.window.show_error(_('Keystore not found in this wallet'))
            return
        self._enable_keystore(keystore, is_hardware)

    @protected
    def _enable_keystore(self, keystore, is_hardware, password):
        self.accept()
        self.wallet.enable_keystore(keystore, is_hardware, password)
        self.window.gui_object.reload_windows()
