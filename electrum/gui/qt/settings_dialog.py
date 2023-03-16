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

from electrum.i18n import _, languages
from electrum import util, coinchooser, paymentrequest
from electrum.util import base_units_list, event_listener

from electrum.gui import messages

from .util import (ColorScheme, WindowModalDialog, HelpLabel, Buttons,
                   CloseButton, QtEventListener)


if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
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
                self.app.update_status_signal.emit()
        nz.valueChanged.connect(on_nz)

        # lightning
        help_trampoline = _(messages.MSG_HELP_TRAMPOLINE)
        trampoline_cb = QCheckBox(_("Use trampoline routing"))
        trampoline_cb.setToolTip(messages.to_rtf(help_trampoline))
        trampoline_cb.setChecked(not bool(self.config.get('use_gossip', False)))
        def on_trampoline_checked(use_trampoline):
            use_trampoline = bool(use_trampoline)
            if not use_trampoline:
                if not window.question('\n'.join([
                        _("Are you sure you want to disable trampoline?"),
                        _("Without this option, Electrum will need to sync with the Lightning network on every start."),
                        _("This may impact the reliability of your payments."),
                ])):
                    trampoline_cb.setCheckState(Qt.Checked)
                    return
            self.config.set_key('use_gossip', not use_trampoline)
            if not use_trampoline:
                self.network.start_gossip()
            else:
                self.network.run_from_another_thread(
                    self.network.stop_gossip())
            util.trigger_callback('ln_gossip_sync_progress')
            # FIXME: update all wallet windows
            util.trigger_callback('channels_updated', self.wallet)
        trampoline_cb.stateChanged.connect(on_trampoline_checked)

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
               + '\n1 BTC = 1000 mBTC. 1 mBTC = 1000 bits. 1 bit = 100 sat.\n'
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

        thousandsep_cb = QCheckBox(_("Add thousand separators to bitcoin amounts"))
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
        self.history_rates_cb = QCheckBox(_('Download historical rates'))
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        def update_currencies():
            if not self.fx:
                return
            h = self.config.get('history_rates', False)
            currencies = sorted(self.fx.get_currencies(h))
            ccy_combo.clear()
            ccy_combo.addItems([_('None')] + currencies)
            if self.fx.is_enabled():
                ccy_combo.setCurrentIndex(ccy_combo.findText(self.fx.get_currency()))

        def update_exchanges():
            if not self.fx: return
            b = self.fx.is_enabled()
            ex_combo.setEnabled(b)
            if b:
                h = self.config.get('history_rates', False)
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
            update_exchanges()
            self.app.update_fiat_signal.emit()

        def on_exchange(idx):
            exchange = str(ex_combo.currentText())
            if self.fx and self.fx.is_enabled() and exchange and exchange != self.fx.exchange.name():
                self.fx.set_exchange(exchange)
            self.app.update_fiat_signal.emit()

        def on_history_rates(checked):
            self.config.set_key('history_rates', bool(checked))
            if not self.fx:
                return
            update_exchanges()
            window.app.update_fiat_signal.emit()

        update_currencies()
        update_exchanges()
        ccy_combo.currentIndexChanged.connect(on_currency)
        self.history_rates_cb.setChecked(self.config.get('history_rates', False))
        self.history_rates_cb.stateChanged.connect(on_history_rates)
        ex_combo.currentIndexChanged.connect(on_exchange)

        gui_widgets = []
        gui_widgets.append((lang_label, lang_combo))
        gui_widgets.append((colortheme_label, colortheme_combo))
        gui_widgets.append((block_ex_label, block_ex_hbox_w))
        units_widgets = []
        units_widgets.append((unit_label, unit_combo))
        units_widgets.append((nz_label, nz))
        units_widgets.append((msat_cb, None))
        units_widgets.append((thousandsep_cb, None))
        lightning_widgets = []
        lightning_widgets.append((trampoline_cb, None))
        lightning_widgets.append((remote_wt_cb, self.watchtower_url_e))
        fiat_widgets = []
        fiat_widgets.append((QLabel(_('Fiat currency')), ccy_combo))
        fiat_widgets.append((QLabel(_('Source')), ex_combo))
        fiat_widgets.append((self.history_rates_cb, None))
        misc_widgets = []
        misc_widgets.append((updatecheck_cb, None))
        misc_widgets.append((filelogging_cb, None))
        misc_widgets.append((alias_label, self.alias_e))
        misc_widgets.append((qr_label, qr_combo))
        if len(choosers) > 1:
            misc_widgets.append((chooser_label, chooser_combo))

        tabs_info = [
            (gui_widgets, _('Appearance')),
            (units_widgets, _('Units')),
            (fiat_widgets, _('Fiat')),
            (lightning_widgets, _('Lightning')),
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
