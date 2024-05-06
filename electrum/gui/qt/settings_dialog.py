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
                             QPushButton, QWidget, QHBoxLayout, QSlider)

from electrum.i18n import _, languages
from electrum import util, paymentrequest
from electrum.util import base_units_list, event_listener

from electrum.gui import messages

from .util import (ColorScheme, WindowModalDialog, HelpLabel, Buttons,
                   CloseButton, QtEventListener)


if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig, ConfigVarWithConfig
    from .main_window import ElectrumWindow


def checkbox_from_configvar(cv: 'ConfigVarWithConfig') -> QCheckBox:
    short_desc = cv.get_short_desc()
    assert short_desc is not None, f"short_desc missing for {cv}"
    cb = QCheckBox(short_desc)
    if (long_desc := cv.get_long_desc()) is not None:
        cb.setToolTip(messages.to_rtf(long_desc))
    return cb


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
        lang_label = HelpLabel.from_configvar(self.config.cv.LOCALIZATION_LANGUAGE)
        lang_combo = QComboBox()
        lang_combo.addItems(list(languages.values()))
        lang_keys = list(languages.keys())
        lang_cur_setting = self.config.LOCALIZATION_LANGUAGE
        try:
            index = lang_keys.index(lang_cur_setting)
        except ValueError:  # not in list
            index = 0
        lang_combo.setCurrentIndex(index)
        if not self.config.cv.LOCALIZATION_LANGUAGE.is_modifiable():
            for w in [lang_combo, lang_label]: w.setEnabled(False)
        def on_lang(x):
            lang_request = list(languages.keys())[lang_combo.currentIndex()]
            if lang_request != self.config.LOCALIZATION_LANGUAGE:
                self.config.LOCALIZATION_LANGUAGE = lang_request
                self.need_restart = True
        lang_combo.currentIndexChanged.connect(on_lang)

        nz_label = HelpLabel.from_configvar(self.config.cv.BTC_AMOUNTS_FORCE_NZEROS_AFTER_DECIMAL_POINT)
        nz = QSpinBox()
        nz.setMinimum(0)
        nz.setMaximum(self.config.decimal_point)
        nz.setValue(self.config.num_zeros)
        if not self.config.cv.BTC_AMOUNTS_FORCE_NZEROS_AFTER_DECIMAL_POINT.is_modifiable():
            for w in [nz, nz_label]: w.setEnabled(False)
        def on_nz():
            value = nz.value()
            if self.config.num_zeros != value:
                self.config.num_zeros = value
                self.config.BTC_AMOUNTS_FORCE_NZEROS_AFTER_DECIMAL_POINT = value
                self.app.refresh_tabs_signal.emit()
                self.app.update_status_signal.emit()
        nz.valueChanged.connect(on_nz)

        # lightning
        trampoline_cb = checkbox_from_configvar(self.config.cv.LIGHTNING_USE_GOSSIP)
        trampoline_cb.setChecked(not self.config.LIGHTNING_USE_GOSSIP)
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
            self.config.LIGHTNING_USE_GOSSIP = not use_trampoline
            if not use_trampoline:
                self.network.start_gossip()
            else:
                self.network.run_from_another_thread(
                    self.network.stop_gossip())
            util.trigger_callback('ln_gossip_sync_progress')
            # FIXME: update all wallet windows
            util.trigger_callback('channels_updated', self.wallet)
        trampoline_cb.stateChanged.connect(on_trampoline_checked)

        legacy_add_trampoline_cb = checkbox_from_configvar(self.config.cv.LIGHTNING_LEGACY_ADD_TRAMPOLINE)
        legacy_add_trampoline_cb.setChecked(self.config.LIGHTNING_LEGACY_ADD_TRAMPOLINE)
        def on_legacy_add_trampoline_checked(b):
            self.config.LIGHTNING_LEGACY_ADD_TRAMPOLINE = bool(b)
        legacy_add_trampoline_cb.stateChanged.connect(on_legacy_add_trampoline_checked)

        remote_wt_cb = checkbox_from_configvar(self.config.cv.WATCHTOWER_CLIENT_ENABLED)
        remote_wt_cb.setChecked(self.config.WATCHTOWER_CLIENT_ENABLED)
        def on_remote_wt_checked(x):
            self.config.WATCHTOWER_CLIENT_ENABLED = bool(x)
            self.watchtower_url_e.setEnabled(bool(x))
        remote_wt_cb.stateChanged.connect(on_remote_wt_checked)
        watchtower_url = self.config.WATCHTOWER_CLIENT_URL
        self.watchtower_url_e = QLineEdit(watchtower_url)
        self.watchtower_url_e.setEnabled(self.config.WATCHTOWER_CLIENT_ENABLED)
        def on_wt_url():
            url = self.watchtower_url_e.text() or None
            self.config.WATCHTOWER_CLIENT_URL = url
        self.watchtower_url_e.editingFinished.connect(on_wt_url)

        lnfee_hlabel = HelpLabel.from_configvar(self.config.cv.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS)
        lnfee_map = [500, 1_000, 3_000, 5_000, 10_000, 20_000, 30_000, 50_000]
        def lnfee_update_vlabel(fee_val: int):
            lnfee_vlabel.setText(_("{}% of payment").format(f"{fee_val / 10 ** 4:.2f}"))
        def lnfee_slider_moved():
            pos = lnfee_slider.sliderPosition()
            fee_val = lnfee_map[pos]
            lnfee_update_vlabel(fee_val)
        def lnfee_slider_released():
            pos = lnfee_slider.sliderPosition()
            fee_val = lnfee_map[pos]
            self.config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS = fee_val
        lnfee_slider = QSlider(Qt.Horizontal)
        lnfee_slider.setRange(0, len(lnfee_map)-1)
        lnfee_slider.setTracking(True)
        try:
            lnfee_spos = lnfee_map.index(self.config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS)
        except ValueError:
            lnfee_spos = 0
        lnfee_slider.setSliderPosition(lnfee_spos)
        lnfee_vlabel = QLabel("")
        lnfee_update_vlabel(self.config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS)
        lnfee_slider.valueChanged.connect(lnfee_slider_moved)
        lnfee_slider.sliderReleased.connect(lnfee_slider_released)
        lnfee_hbox = QHBoxLayout()
        lnfee_hbox.setContentsMargins(0, 0, 0, 0)
        lnfee_hbox.addWidget(lnfee_vlabel)
        lnfee_hbox.addWidget(lnfee_slider)
        lnfee_hbox_w = QWidget()
        lnfee_hbox_w.setLayout(lnfee_hbox)

        alias_label = HelpLabel.from_configvar(self.config.cv.OPENALIAS_ID)
        alias = self.config.OPENALIAS_ID
        self.alias_e = QLineEdit(alias)
        self.set_alias_color()
        self.alias_e.editingFinished.connect(self.on_alias_edit)

        msat_cb = checkbox_from_configvar(self.config.cv.BTC_AMOUNTS_PREC_POST_SAT)
        msat_cb.setChecked(self.config.BTC_AMOUNTS_PREC_POST_SAT > 0)
        def on_msat_checked(v):
            prec = 3 if v == Qt.Checked else 0
            if self.config.amt_precision_post_satoshi != prec:
                self.config.amt_precision_post_satoshi = prec
                self.config.BTC_AMOUNTS_PREC_POST_SAT = prec
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

        thousandsep_cb = checkbox_from_configvar(self.config.cv.BTC_AMOUNTS_ADD_THOUSANDS_SEP)
        thousandsep_cb.setChecked(self.config.BTC_AMOUNTS_ADD_THOUSANDS_SEP)
        def on_set_thousandsep(v):
            checked = v == Qt.Checked
            if self.config.amt_add_thousands_sep != checked:
                self.config.amt_add_thousands_sep = checked
                self.config.BTC_AMOUNTS_ADD_THOUSANDS_SEP = checked
                self.app.refresh_tabs_signal.emit()
        thousandsep_cb.stateChanged.connect(on_set_thousandsep)

        qr_combo = QComboBox()
        qr_combo.addItem("Default", "default")
        qr_label = HelpLabel.from_configvar(self.config.cv.VIDEO_DEVICE_PATH)
        from .qrreader import find_system_cameras
        system_cameras = find_system_cameras()
        for cam_desc, cam_path in system_cameras.items():
            qr_combo.addItem(cam_desc, cam_path)
        index = qr_combo.findData(self.config.VIDEO_DEVICE_PATH)
        qr_combo.setCurrentIndex(index)
        def on_video_device(x):
            self.config.VIDEO_DEVICE_PATH = qr_combo.itemData(x)
        qr_combo.currentIndexChanged.connect(on_video_device)

        colortheme_combo = QComboBox()
        colortheme_combo.addItem(_('Light'), 'default')
        colortheme_combo.addItem(_('Dark'), 'dark')
        index = colortheme_combo.findData(self.config.GUI_QT_COLOR_THEME)
        colortheme_combo.setCurrentIndex(index)
        colortheme_label = QLabel(self.config.cv.GUI_QT_COLOR_THEME.get_short_desc() + ':')
        def on_colortheme(x):
            self.config.GUI_QT_COLOR_THEME = colortheme_combo.itemData(x)
            self.need_restart = True
        colortheme_combo.currentIndexChanged.connect(on_colortheme)

        updatecheck_cb = checkbox_from_configvar(self.config.cv.AUTOMATIC_CENTRALIZED_UPDATE_CHECKS)
        updatecheck_cb.setChecked(self.config.AUTOMATIC_CENTRALIZED_UPDATE_CHECKS)
        def on_set_updatecheck(v):
            self.config.AUTOMATIC_CENTRALIZED_UPDATE_CHECKS = (v == Qt.Checked)
        updatecheck_cb.stateChanged.connect(on_set_updatecheck)

        filelogging_cb = checkbox_from_configvar(self.config.cv.WRITE_LOGS_TO_DISK)
        filelogging_cb.setChecked(self.config.WRITE_LOGS_TO_DISK)
        def on_set_filelogging(v):
            self.config.WRITE_LOGS_TO_DISK = (v == Qt.Checked)
            self.need_restart = True
        filelogging_cb.stateChanged.connect(on_set_filelogging)

        block_explorers = sorted(util.block_explorer_info().keys())
        BLOCK_EX_CUSTOM_ITEM = _("Custom URL")
        if BLOCK_EX_CUSTOM_ITEM in block_explorers:  # malicious translation?
            block_explorers.remove(BLOCK_EX_CUSTOM_ITEM)
        block_explorers.append(BLOCK_EX_CUSTOM_ITEM)
        block_ex_label = HelpLabel.from_configvar(self.config.cv.BLOCK_EXPLORER)
        block_ex_combo = QComboBox()
        block_ex_custom_e = QLineEdit(str(self.config.BLOCK_EXPLORER_CUSTOM or ''))
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
                self.config.BLOCK_EXPLORER_CUSTOM = None
                self.config.BLOCK_EXPLORER = be_result
            showhide_block_ex_custom_e()
        block_ex_combo.currentIndexChanged.connect(on_be_combo)
        def on_be_edit():
            val = block_ex_custom_e.text()
            try:
                val = ast.literal_eval(val)  # to also accept tuples
            except Exception:
                pass
            self.config.BLOCK_EXPLORER_CUSTOM = val
        block_ex_custom_e.editingFinished.connect(on_be_edit)
        block_ex_hbox = QHBoxLayout()
        block_ex_hbox.setContentsMargins(0, 0, 0, 0)
        block_ex_hbox.setSpacing(0)
        block_ex_hbox.addWidget(block_ex_combo)
        block_ex_hbox.addWidget(block_ex_custom_e)
        block_ex_hbox_w = QWidget()
        block_ex_hbox_w.setLayout(block_ex_hbox)

        # Fiat Currency
        self.history_rates_cb = checkbox_from_configvar(self.config.cv.FX_HISTORY_RATES)
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        def update_currencies():
            if not self.fx:
                return
            h = self.config.FX_HISTORY_RATES
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
                h = self.config.FX_HISTORY_RATES
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
            self.config.FX_HISTORY_RATES = bool(checked)
            if not self.fx:
                return
            update_exchanges()
            window.app.update_fiat_signal.emit()

        update_currencies()
        update_exchanges()
        ccy_combo.currentIndexChanged.connect(on_currency)
        self.history_rates_cb.setChecked(self.config.FX_HISTORY_RATES)
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
        lightning_widgets.append((legacy_add_trampoline_cb, None))
        lightning_widgets.append((remote_wt_cb, self.watchtower_url_e))
        lightning_widgets.append((lnfee_hlabel, lnfee_hbox_w))
        fiat_widgets = []
        fiat_widgets.append((QLabel(_('Fiat currency')), ccy_combo))
        fiat_widgets.append((QLabel(_('Source')), ex_combo))
        fiat_widgets.append((self.history_rates_cb, None))
        misc_widgets = []
        misc_widgets.append((updatecheck_cb, None))
        misc_widgets.append((filelogging_cb, None))
        misc_widgets.append((alias_label, self.alias_e))
        misc_widgets.append((qr_label, qr_combo))

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
        if not self.config.OPENALIAS_ID:
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
        self.config.OPENALIAS_ID = alias
        if alias:
            self.wallet.contacts.fetch_openalias(self.config)

    def closeEvent(self, event):
        self.unregister_callbacks()
        try:
            self.app.alias_received_signal.disconnect(self.set_alias_color)
        except TypeError:
            pass  # 'method' object is not connected
        event.accept()
