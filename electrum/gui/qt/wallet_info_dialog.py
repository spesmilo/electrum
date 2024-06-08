# Copyright (C) 2023 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import os
from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QPushButton, QWidget, QStackedWidget)

from electrum import keystore
from electrum.plugin import run_hook
from electrum.i18n import _
from electrum.wallet import Multisig_Wallet

from .qrtextedit import ShowQRTextEdit
from .util import (read_QIcon, WindowModalDialog, ChoicesLayout, Buttons,
                   WWLabel, CloseButton, HelpButton, font_height, ShowQRLineEdit)

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class WalletInfoDialog(WindowModalDialog):

    def __init__(self, parent: QWidget, *, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, parent, _("Wallet Information"))
        self.setMinimumSize(800, 100)
        wallet = window.wallet
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

            ks_stack = QStackedWidget()

            def select_ks(index):
                ks_stack.setCurrentIndex(index)

            # only show the combobox in case multiple accounts are available
            if len(keystores) > 1:
                def label(idx, ks):
                    if isinstance(wallet, Multisig_Wallet) and hasattr(ks, 'label'):
                        return _("cosigner") + f' {idx+1}: {ks.get_type_text()} {ks.label}'
                    else:
                        return _("keystore") + f' {idx+1}'

                labels = [label(idx, ks) for idx, ks in enumerate(wallet.get_keystores())]

                on_click = lambda clayout: select_ks(clayout.selected_index())
                labels_clayout = ChoicesLayout(_("Select keystore"), labels, on_click)
                vbox.addLayout(labels_clayout.layout())

            for ks in keystores:
                ks_w = QWidget()
                ks_vbox = QVBoxLayout()
                ks_vbox.setContentsMargins(0, 0, 0, 0)
                ks_w.setLayout(ks_vbox)

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
                der_path_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
                der_path_hbox.addWidget(der_path_text)
                der_path_hbox.addStretch()
                ks_vbox.addLayout(der_path_hbox)

                bip32fp_hbox = QHBoxLayout()
                bip32fp_hbox.setContentsMargins(0, 0, 0, 0)
                bip32fp_hbox.addWidget(QLabel("BIP32 root fingerprint:"))
                bip32fp_text = WWLabel(ks.get_root_fingerprint() or _("unknown"))
                bip32fp_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
                bip32fp_hbox.addWidget(bip32fp_text)
                bip32fp_hbox.addStretch()
                ks_vbox.addLayout(bip32fp_hbox)

                ks_stack.addWidget(ks_w)

            select_ks(0)
            vbox.addWidget(ks_stack)

        vbox.addStretch(1)
        btn_export_info = run_hook('wallet_info_buttons', window, self)
        btn_close = CloseButton(self)
        btns = Buttons(btn_export_info, btn_close)
        vbox.addLayout(btns)
        self.setLayout(vbox)
