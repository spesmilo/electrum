#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import ast
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QComboBox,  QTabWidget, QDialog,
                             QSpinBox,  QFileDialog, QCheckBox, QLabel,
                             QVBoxLayout, QGridLayout, QLineEdit,
                             QPushButton, QWidget, QHBoxLayout)

from electrum_ltc.i18n import _, languages
from electrum_ltc import util, coinchooser, paymentrequest
from electrum_ltc.util import base_units_list, event_listener

from electrum_ltc.gui import messages

from .util import (ColorScheme, WindowModalDialog, HelpLabel, Buttons,
                   CloseButton, QtEventListener)


if TYPE_CHECKING:
    from electrum_ltc.simple_config import SimpleConfig
    from .main_window import ElectrumWindow


class SettingsDialog(QDialog, QtEventListener):

    def __init__(self, window: 'ElectrumWindow', config: 'SimpleConfig'):
        QDialog.__init__(self)
        self.setWindowTitle(_('Preferences'))
        self.setMinimumWidth(500)
        self.config = config
        self.network = window.network
        self.app = window.app
        self.need_restart = False
        self.fx = window.fx
        self.wallet = window.wallet

        self.register_callbacks()
        self.app.alias_received_signal.connect(self.set_alias_color)

        vbox = QVBoxLayout()
        tabs = QTabWidget()

        # language
        lang_help = _('Select which language is used in the GUI (after restart).')
        lang_label = HelpLabel(_('Language') + ':', lang_help)
        lang_combo = QComboBox()
        lang_combo.addItems(list(languages.values()))
        lang_keys = list(languages.keys())
        lang_cur_setting = self.config.get("language", '')
        try:
            index = lang_keys.index(lang_cur_setting)
        except ValueError:  # not in list
            index = 0
        lang_combo.setCurrentIndex(index)
        if not self.config.is_modifiable('language'):
            for w in [lang_combo, lang_label]: w.setEnabled(False)
        def on_lang(x):
            lang_request = list(languages.keys())[lang_combo.currentIndex()]
            if lang_request != self.config.get('language'):
                self.config.set_key("language", lang_request, True)
                self.need_restart = True
        lang_combo.currentIndexChanged.connect(on_lang)

        nz_help = _('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"')
        nz_label = HelpLabel(_('Zeros after decimal point') + ':', nz_help)
        nz = QSpinBox()
        nz.setMinimum(0)
        nz.setMaximum(self.config.decimal_point)
        nz.setValue(self.config.num_zeros)
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz, nz_label]: w.setEnabled(False)
        def on_nz():
            value = nz.value()
            if self.config.num_zeros != value:
                self.config.num_zeros = value
                self.config.set_key('num_zeros', value, True)
                self.app.refresh_tabs_signal.emit()
        nz.valueChanged.connect(on_nz)

        # invoices
        bolt11_fallback_cb = QCheckBox(_('Add on-chain fallback to lightning invoices'))
        bolt11_fallback_cb.setChecked(bool(self.config.get('bolt11_fallback', True)))
        bolt11_fallback_cb.setToolTip(_('Add fallback addresses to BOLT11 lightning invoices.'))
        def on_bolt11_fallback(x):
            self.config.set_key('bolt11_fallback', bool(x))
        bolt11_fallback_cb.stateChanged.connect(on_bolt11_fallback)

        bip21_lightning_cb = QCheckBox(_('Add lightning invoice to litecoin URIs'))
        bip21_lightning_cb.setChecked(bool(self.config.get('bip21_lightning', False)))
        bip21_lightning_cb.setToolTip(_('This may create larger qr codes.'))
        def on_bip21_lightning(x):
            self.config.set_key('bip21_lightning', bool(x))
        bip21_lightning_cb.stateChanged.connect(on_bip21_lightning)

        use_rbf = bool(self.config.get('use_rbf', True))
        use_rbf_cb = QCheckBox(_('Use Replace-By-Fee'))
        use_rbf_cb.setChecked(use_rbf)
        use_rbf_cb.setToolTip(
            _('If you check this box, your transactions will be marked as non-final,') + '\n' + \
            _('and you will have the possibility, while they are unconfirmed, to replace them with transactions that pay higher fees.') + '\n' + \
            _('Note that some merchants do not accept non-final transactions until they are confirmed.'))
        def on_use_rbf(x):
            self.config.set_key('use_rbf', bool(x))
            batch_rbf_cb.setEnabled(bool(x))
        use_rbf_cb.stateChanged.connect(on_use_rbf)

        batch_rbf_cb = QCheckBox(_('Batch RBF transactions'))
        batch_rbf_cb.setChecked(bool(self.config.get('batch_rbf', False)))
        batch_rbf_cb.setEnabled(use_rbf)
        batch_rbf_cb.setToolTip(
            _('If you check this box, your unconfirmed transactions will be consolidated into a single transaction.') + '\n' + \
            _('This will save fees.'))
        def on_batch_rbf(x):
            self.config.set_key('batch_rbf', bool(x))
        batch_rbf_cb.stateChanged.connect(on_batch_rbf)

        # lightning
        help_recov = _(messages.MSG_RECOVERABLE_CHANNELS)
        recov_cb = QCheckBox(_("Create recoverable channels"))
        enable_toggle_use_recoverable_channels = bool(self.wallet.lnworker and self.wallet.lnworker.can_have_recoverable_channels())
        recov_cb.setEnabled(enable_toggle_use_recoverable_channels)
        recov_cb.setToolTip(messages.to_rtf(help_recov))
        recov_cb.setChecked(bool(self.config.get('use_recoverable_channels', True)) and enable_toggle_use_recoverable_channels)
        def on_recov_checked(x):
            self.config.set_key('use_recoverable_channels', bool(x))
        recov_cb.stateChanged.connect(on_recov_checked)

        help_trampoline = _(messages.MSG_HELP_TRAMPOLINE)
        trampoline_cb = QCheckBox(_("Use trampoline routing (disable gossip)"))
        trampoline_cb.setToolTip(messages.to_rtf(help_trampoline))
        trampoline_cb.setChecked(not bool(self.config.get('use_gossip', False)))
        def on_trampoline_checked(use_trampoline):
            use_gossip = not bool(use_trampoline)
            self.config.set_key('use_gossip', use_gossip)
            if use_gossip:
                self.network.start_gossip()
            else:
                self.network.run_from_another_thread(
                    self.network.stop_gossip())
            util.trigger_callback('ln_gossip_sync_progress')
            # FIXME: update all wallet windows
            util.trigger_callback('channels_updated', self.wallet)
        trampoline_cb.stateChanged.connect(on_trampoline_checked)

        help_instant_swaps = ' '.join([
            _("If this option is checked, your client will complete reverse swaps before the funding transaction is confirmed."),
            _("Note you are at risk of losing the funds in the swap, if the funding transaction never confirms.")
            ])
        instant_swaps_cb = QCheckBox(_("Allow instant swaps"))
        instant_swaps_cb.setToolTip(messages.to_rtf(help_instant_swaps))
        instant_swaps_cb.setChecked(bool(self.config.get('allow_instant_swaps', False)))
        def on_instant_swaps_checked(allow_instant_swaps):
            self.config.set_key('allow_instant_swaps', bool(allow_instant_swaps))
        instant_swaps_cb.stateChanged.connect(on_instant_swaps_checked)

        help_remote_wt = ' '.join([
            _("A watchtower is a daemon that watches your channels and prevents the other party from stealing funds by broadcasting an old state."),
            _("If you have private a watchtower, enter its URL here."),
            _("Check our online documentation if you want to configure Electrum as a watchtower."),
        ])
        remote_wt_cb = QCheckBox(_("Use a remote watchtower"))
        remote_wt_cb.setToolTip('<p>'+help_remote_wt+'</p>')
        remote_wt_cb.setChecked(bool(self.config.get('use_watchtower', False)))
        def on_remote_wt_checked(x):
            self.config.set_key('use_watchtower', bool(x))
            self.watchtower_url_e.setEnabled(bool(x))
        remote_wt_cb.stateChanged.connect(on_remote_wt_checked)
        watchtower_url = self.config.get('watchtower_url')
        self.watchtower_url_e = QLineEdit(watchtower_url)
        self.watchtower_url_e.setEnabled(self.config.get('use_watchtower', False))
        def on_wt_url():
            url = self.watchtower_url_e.text() or None
            watchtower_url = self.config.set_key('watchtower_url', url)
        self.watchtower_url_e.editingFinished.connect(on_wt_url)

        msg = _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n'\
              + _('The following alias providers are available:') + '\n'\
              + '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n'\
              + 'For more information, see https://openalias.org'
        alias_label = HelpLabel(_('OpenAlias') + ':', msg)
        alias = self.config.get('alias','')
        self.alias_e = QLineEdit(alias)
        self.set_alias_color()
        self.alias_e.editingFinished.connect(self.on_alias_edit)

        msat_cb = QCheckBox(_("Show Lightning amounts with msat precision"))
        msat_cb.setChecked(bool(self.config.get('amt_precision_post_satoshi', False)))
        def on_msat_checked(v):
            prec = 3 if v == Qt.Checked else 0
            if self.config.amt_precision_post_satoshi != prec:
                self.config.amt_precision_post_satoshi = prec
                self.config.set_key('amt_precision_post_satoshi', prec)
                self.app.refresh_tabs_signal.emit()
        msat_cb.stateChanged.connect(on_msat_checked)

        # units
        units = base_units_list
        msg = (_('Base unit of your wallet.')
               + '\n1 LTC = 1000 mLTC. 1 mLTC = 1000 uLTC. 1 uLTC = 100 sat.\n'
               + _('This setting affects the Send tab, and all balance related fields.'))
        unit_label = HelpLabel(_('Base unit') + ':', msg)
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(self.config.get_base_unit()))
        def on_unit(x, nz):
            unit_result = units[unit_combo.currentIndex()]
            if self.config.get_base_unit() == unit_result:
                return
            self.config.set_base_unit(unit_result)
            nz.setMaximum(self.config.decimal_point)
            self.app.refresh_tabs_signal.emit()
            self.app.update_status_signal.emit()
            self.app.refresh_amount_edits_signal.emit()
        unit_combo.currentIndexChanged.connect(lambda x: on_unit(x, nz))

        thousandsep_cb = QCheckBox(_("Add thousand separators to litecoin amounts"))
        thousandsep_cb.setChecked(bool(self.config.get('amt_add_thousands_sep', False)))
        def on_set_thousandsep(v):
            checked = v == Qt.Checked
            if self.config.amt_add_thousands_sep != checked:
                self.config.amt_add_thousands_sep = checked
                self.config.set_key('amt_add_thousands_sep', checked)
                self.app.refresh_tabs_signal.emit()
        thousandsep_cb.stateChanged.connect(on_set_thousandsep)

        qr_combo = QComboBox()
        qr_combo.addItem("Default", "default")
        msg = (_("For scanning QR codes.") + "\n"
               + _("Install the zbar package to enable this."))
        qr_label = HelpLabel(_('Video Device') + ':', msg)
        from .qrreader import find_system_cameras
        system_cameras = find_system_cameras()
        for cam_desc, cam_path in system_cameras.items():
            qr_combo.addItem(cam_desc, cam_path)
        index = qr_combo.findData(self.config.get("video_device"))
        qr_combo.setCurrentIndex(index)
        on_video_device = lambda x: self.config.set_key("video_device", qr_combo.itemData(x), True)
        qr_combo.currentIndexChanged.connect(on_video_device)

        colortheme_combo = QComboBox()
        colortheme_combo.addItem(_('Light'), 'default')
        colortheme_combo.addItem(_('Dark'), 'dark')
        index = colortheme_combo.findData(self.config.get('qt_gui_color_theme', 'default'))
        colortheme_combo.setCurrentIndex(index)
        colortheme_label = QLabel(_('Color theme') + ':')
        def on_colortheme(x):
            self.config.set_key('qt_gui_color_theme', colortheme_combo.itemData(x), True)
            self.need_restart = True
        colortheme_combo.currentIndexChanged.connect(on_colortheme)

        updatecheck_cb = QCheckBox(_("Automatically check for software updates"))
        updatecheck_cb.setChecked(bool(self.config.get('check_updates', False)))
        def on_set_updatecheck(v):
            self.config.set_key('check_updates', v == Qt.Checked, save=True)
        updatecheck_cb.stateChanged.connect(on_set_updatecheck)

        filelogging_cb = QCheckBox(_("Write logs to file"))
        filelogging_cb.setChecked(bool(self.config.get('log_to_file', False)))
        def on_set_filelogging(v):
            self.config.set_key('log_to_file', v == Qt.Checked, save=True)
            self.need_restart = True
        filelogging_cb.stateChanged.connect(on_set_filelogging)
        filelogging_cb.setToolTip(_('Debug logs can be persisted to disk. These are useful for troubleshooting.'))

        preview_cb = QCheckBox(_('Advanced preview'))
        preview_cb.setChecked(bool(self.config.get('advanced_preview', False)))
        preview_cb.setToolTip(_("Open advanced transaction preview dialog when 'Pay' is clicked."))
        def on_preview(x):
            self.config.set_key('advanced_preview', x == Qt.Checked)
        preview_cb.stateChanged.connect(on_preview)

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(self.wallet.use_change)
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)
        def on_usechange(x):
            usechange_result = x == Qt.Checked
            if self.wallet.use_change != usechange_result:
                self.wallet.use_change = usechange_result
                self.wallet.db.put('use_change', self.wallet.use_change)
                multiple_cb.setEnabled(self.wallet.use_change)
        usechange_cb.stateChanged.connect(on_usechange)
        usechange_cb.setToolTip(_('Using change addresses makes it more difficult for other people to track your transactions.'))

        def on_multiple(x):
            multiple = x == Qt.Checked
            if self.wallet.multiple_change != multiple:
                self.wallet.multiple_change = multiple
                self.wallet.db.put('multiple_change', multiple)
        multiple_change = self.wallet.multiple_change
        multiple_cb = QCheckBox(_('Use multiple change addresses'))
        multiple_cb.setEnabled(self.wallet.use_change)
        multiple_cb.setToolTip('\n'.join([
            _('In some cases, use up to 3 change addresses in order to break '
              'up large coin amounts and obfuscate the recipient address.'),
            _('This may result in higher transactions fees.')
        ]))
        multiple_cb.setChecked(multiple_change)
        multiple_cb.stateChanged.connect(on_multiple)

        def fmt_docs(key, klass):
            lines = [ln.lstrip(" ") for ln in klass.__doc__.split("\n")]
            return '\n'.join([key, "", " ".join(lines)])

        choosers = sorted(coinchooser.COIN_CHOOSERS.keys())
        if len(choosers) > 1:
            chooser_name = coinchooser.get_name(self.config)
            msg = _('Choose coin (UTXO) selection method.  The following are available:\n\n')
            msg += '\n\n'.join(fmt_docs(*item) for item in coinchooser.COIN_CHOOSERS.items())
            chooser_label = HelpLabel(_('Coin selection') + ':', msg)
            chooser_combo = QComboBox()
            chooser_combo.addItems(choosers)
            i = choosers.index(chooser_name) if chooser_name in choosers else 0
            chooser_combo.setCurrentIndex(i)
            def on_chooser(x):
                chooser_name = choosers[chooser_combo.currentIndex()]
                self.config.set_key('coin_chooser', chooser_name)
            chooser_combo.currentIndexChanged.connect(on_chooser)

        def on_unconf(x):
            self.config.set_key('confirmed_only', bool(x))
        conf_only = bool(self.config.get('confirmed_only', False))
        unconf_cb = QCheckBox(_('Spend only confirmed coins'))
        unconf_cb.setToolTip(_('Spend only confirmed inputs.'))
        unconf_cb.setChecked(conf_only)
        unconf_cb.stateChanged.connect(on_unconf)

        def on_outrounding(x):
            self.config.set_key('coin_chooser_output_rounding', bool(x))
        enable_outrounding = bool(self.config.get('coin_chooser_output_rounding', True))
        outrounding_cb = QCheckBox(_('Enable output value rounding'))
        outrounding_cb.setToolTip(
            _('Set the value of the change output so that it has similar precision to the other outputs.') + '\n' +
            _('This might improve your privacy somewhat.') + '\n' +
            _('If enabled, at most 100 satoshis might be lost due to this, per transaction.'))
        outrounding_cb.setChecked(enable_outrounding)
        outrounding_cb.stateChanged.connect(on_outrounding)

        block_explorers = sorted(util.block_explorer_info().keys())
        BLOCK_EX_CUSTOM_ITEM = _("Custom URL")
        if BLOCK_EX_CUSTOM_ITEM in block_explorers:  # malicious translation?
            block_explorers.remove(BLOCK_EX_CUSTOM_ITEM)
        block_explorers.append(BLOCK_EX_CUSTOM_ITEM)
        msg = _('Choose which online block explorer to use for functions that open a web browser')
        block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_ex_combo = QComboBox()
        block_ex_custom_e = QLineEdit(str(self.config.get('block_explorer_custom') or ''))
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(
            block_ex_combo.findText(util.block_explorer(self.config) or BLOCK_EX_CUSTOM_ITEM))
        def showhide_block_ex_custom_e():
            block_ex_custom_e.setVisible(block_ex_combo.currentText() == BLOCK_EX_CUSTOM_ITEM)
        showhide_block_ex_custom_e()
        def on_be_combo(x):
            if block_ex_combo.currentText() == BLOCK_EX_CUSTOM_ITEM:
                on_be_edit()
            else:
                be_result = block_explorers[block_ex_combo.currentIndex()]
                self.config.set_key('block_explorer_custom', None, False)
                self.config.set_key('block_explorer', be_result, True)
            showhide_block_ex_custom_e()
        block_ex_combo.currentIndexChanged.connect(on_be_combo)
        def on_be_edit():
            val = block_ex_custom_e.text()
            try:
                val = ast.literal_eval(val)  # to also accept tuples
            except:
                pass
            self.config.set_key('block_explorer_custom', val)
        block_ex_custom_e.editingFinished.connect(on_be_edit)
        block_ex_hbox = QHBoxLayout()
        block_ex_hbox.setContentsMargins(0, 0, 0, 0)
        block_ex_hbox.setSpacing(0)
        block_ex_hbox.addWidget(block_ex_combo)
        block_ex_hbox.addWidget(block_ex_custom_e)
        block_ex_hbox_w = QWidget()
        block_ex_hbox_w.setLayout(block_ex_hbox)

        # Fiat Currency
        hist_checkbox = QCheckBox()
        hist_capgains_checkbox = QCheckBox()
        fiat_address_checkbox = QCheckBox()
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        def update_currencies():
            if not self.fx:
                return
            currencies = sorted(self.fx.get_currencies(self.fx.get_history_config()))
            ccy_combo.clear()
            ccy_combo.addItems([_('None')] + currencies)
            if self.fx.is_enabled():
                ccy_combo.setCurrentIndex(ccy_combo.findText(self.fx.get_currency()))

        def update_history_cb():
            if not self.fx: return
            hist_checkbox.setChecked(self.fx.get_history_config())
            hist_checkbox.setEnabled(self.fx.is_enabled())

        def update_fiat_address_cb():
            if not self.fx: return
            fiat_address_checkbox.setChecked(self.fx.get_fiat_address_config())

        def update_history_capgains_cb():
            if not self.fx: return
            hist_capgains_checkbox.setChecked(self.fx.get_history_capital_gains_config())
            hist_capgains_checkbox.setEnabled(hist_checkbox.isChecked())

        def update_exchanges():
            if not self.fx: return
            b = self.fx.is_enabled()
            ex_combo.setEnabled(b)
            if b:
                h = self.fx.get_history_config()
                c = self.fx.get_currency()
                exchanges = self.fx.get_exchanges_by_ccy(c, h)
            else:
                exchanges = self.fx.get_exchanges_by_ccy('USD', False)
            ex_combo.blockSignals(True)
            ex_combo.clear()
            ex_combo.addItems(sorted(exchanges))
            ex_combo.setCurrentIndex(ex_combo.findText(self.fx.config_exchange()))
            ex_combo.blockSignals(False)

        def on_currency(hh):
            if not self.fx: return
            b = bool(ccy_combo.currentIndex())
            ccy = str(ccy_combo.currentText()) if b else None
            self.fx.set_enabled(b)
            if b and ccy != self.fx.ccy:
                self.fx.set_currency(ccy)
            update_history_cb()
            update_exchanges()
            self.app.update_fiat_signal.emit()

        def on_exchange(idx):
            exchange = str(ex_combo.currentText())
            if self.fx and self.fx.is_enabled() and exchange and exchange != self.fx.exchange.name():
                self.fx.set_exchange(exchange)

        def on_history(checked):
            if not self.fx: return
            self.fx.set_history_config(checked)
            update_exchanges()
            if self.fx.is_enabled() and checked:
                self.fx.trigger_update()
            update_history_capgains_cb()
            self.app.update_fiat_signal.emit()

        def on_history_capgains(checked):
            if not self.fx: return
            self.fx.set_history_capital_gains_config(checked)
            self.app.update_fiat_signal.emit()

        def on_fiat_address(checked):
            if not self.fx: return
            self.fx.set_fiat_address_config(checked)
            self.app.update_fiat_signal.emit()

        update_currencies()
        update_history_cb()
        update_history_capgains_cb()
        update_fiat_address_cb()
        update_exchanges()
        ccy_combo.currentIndexChanged.connect(on_currency)
        hist_checkbox.stateChanged.connect(on_history)
        hist_capgains_checkbox.stateChanged.connect(on_history_capgains)
        fiat_address_checkbox.stateChanged.connect(on_fiat_address)
        ex_combo.currentIndexChanged.connect(on_exchange)

        gui_widgets = []
        gui_widgets.append((lang_label, lang_combo))
        gui_widgets.append((colortheme_label, colortheme_combo))
        gui_widgets.append((unit_label, unit_combo))
        gui_widgets.append((nz_label, nz))
        gui_widgets.append((msat_cb, None))
        gui_widgets.append((thousandsep_cb, None))
        invoices_widgets = []
        invoices_widgets.append((bolt11_fallback_cb, None))
        invoices_widgets.append((bip21_lightning_cb, None))
        tx_widgets = []
        tx_widgets.append((usechange_cb, None))
        tx_widgets.append((use_rbf_cb, None))
        tx_widgets.append((batch_rbf_cb, None))
        tx_widgets.append((preview_cb, None))
        tx_widgets.append((unconf_cb, None))
        tx_widgets.append((multiple_cb, None))
        tx_widgets.append((outrounding_cb, None))
        if len(choosers) > 1:
            tx_widgets.append((chooser_label, chooser_combo))
        tx_widgets.append((block_ex_label, block_ex_hbox_w))
        lightning_widgets = []
        lightning_widgets.append((recov_cb, None))
        lightning_widgets.append((trampoline_cb, None))
        lightning_widgets.append((instant_swaps_cb, None))
        lightning_widgets.append((remote_wt_cb, self.watchtower_url_e))
        fiat_widgets = []
        fiat_widgets.append((QLabel(_('Fiat currency')), ccy_combo))
        fiat_widgets.append((QLabel(_('Source')), ex_combo))
        fiat_widgets.append((QLabel(_('Show history rates')), hist_checkbox))
        fiat_widgets.append((QLabel(_('Show capital gains in history')), hist_capgains_checkbox))
        fiat_widgets.append((QLabel(_('Show Fiat balance for addresses')), fiat_address_checkbox))
        misc_widgets = []
        misc_widgets.append((updatecheck_cb, None))
        misc_widgets.append((filelogging_cb, None))
        misc_widgets.append((alias_label, self.alias_e))
        misc_widgets.append((qr_label, qr_combo))

        tabs_info = [
            (gui_widgets, _('Appearance')),
            (tx_widgets, _('Transactions')),
            (invoices_widgets, _('Invoices')),
            (lightning_widgets, _('Lightning')),
            (fiat_widgets, _('Fiat')),
            (misc_widgets, _('Misc')),
        ]
        for widgets, name in tabs_info:
            tab = QWidget()
            tab_vbox = QVBoxLayout(tab)
            grid = QGridLayout()
            for a,b in widgets:
                i = grid.rowCount()
                if b:
                    if a:
                        grid.addWidget(a, i, 0)
                    grid.addWidget(b, i, 1)
                else:
                    grid.addWidget(a, i, 0, 1, 2)
            tab_vbox.addLayout(grid)
            tab_vbox.addStretch(1)
            tabs.addTab(tab, name)

        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)

    @event_listener
    def on_event_alias_received(self):
        self.app.alias_received_signal.emit()

    def set_alias_color(self):
        if not self.config.get('alias'):
            self.alias_e.setStyleSheet("")
            return
        if self.wallet.contacts.alias_info:
            alias_addr, alias_name, validated = self.wallet.contacts.alias_info
            self.alias_e.setStyleSheet((ColorScheme.GREEN if validated else ColorScheme.RED).as_stylesheet(True))
        else:
            self.alias_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))

    def on_alias_edit(self):
        self.alias_e.setStyleSheet("")
        alias = str(self.alias_e.text())
        self.config.set_key('alias', alias, True)
        if alias:
            self.wallet.contacts.fetch_openalias(self.config)

    def closeEvent(self, event):
        self.unregister_callbacks()
        try:
            self.app.alias_received_signal.disconnect(self.set_alias_color)
        except TypeError:
            pass  # 'method' object is not connected
        event.accept()
