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

from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QComboBox,  QTabWidget,
                             QSpinBox,  QFileDialog, QCheckBox, QLabel,
                             QVBoxLayout, QGridLayout, QLineEdit,
                             QPushButton, QWidget)

from electrum.i18n import _
from electrum import util, coinchooser, paymentrequest
from electrum.util import base_units_list, base_unit_name_to_decimal_point

from .util import (ColorScheme, WindowModalDialog, HelpLabel, Buttons,
                   CloseButton)

from electrum.i18n import languages
from electrum import qrscanner

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from .main_window import ElectrumWindow


class SettingsDialog(WindowModalDialog):

    def __init__(self, parent: 'ElectrumWindow', config: 'SimpleConfig'):
        WindowModalDialog.__init__(self, parent, _('Preferences'))
        self.config = config
        self.window = parent
        self.need_restart = False
        self.fx = self.window.fx
        self.wallet = self.window.wallet
        
        vbox = QVBoxLayout()
        tabs = QTabWidget()
        gui_widgets = []
        fee_widgets = []
        tx_widgets = []
        oa_widgets = []
        services_widgets = []

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
        gui_widgets.append((lang_label, lang_combo))

        nz_help = _('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"')
        nz_label = HelpLabel(_('Zeros after decimal point') + ':', nz_help)
        nz = QSpinBox()
        nz.setMinimum(0)
        nz.setMaximum(self.window.decimal_point)
        nz.setValue(self.window.num_zeros)
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz, nz_label]: w.setEnabled(False)
        def on_nz():
            value = nz.value()
            if self.window.num_zeros != value:
                self.window.num_zeros = value
                self.config.set_key('num_zeros', value, True)
                self.window.history_list.update()
                self.window.address_list.update()
        nz.valueChanged.connect(on_nz)
        gui_widgets.append((nz_label, nz))

        msg = '\n'.join([
            _('Time based: fee rate is based on average confirmation time estimates'),
            _('Mempool based: fee rate is targeting a depth in the memory pool')
            ]
        )
        fee_type_label = HelpLabel(_('Fee estimation') + ':', msg)
        fee_type_combo = QComboBox()
        fee_type_combo.addItems([_('Static'), _('ETA'), _('Mempool')])
        fee_type_combo.setCurrentIndex((2 if self.config.use_mempool_fees() else 1) if self.config.is_dynfee() else 0)
        def on_fee_type(x):
            self.config.set_key('mempool_fees', x==2)
            self.config.set_key('dynamic_fees', x>0)
        fee_type_combo.currentIndexChanged.connect(on_fee_type)
        fee_widgets.append((fee_type_label, fee_type_combo))

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
        fee_widgets.append((use_rbf_cb, None))

        batch_rbf_cb = QCheckBox(_('Batch RBF transactions'))
        batch_rbf_cb.setChecked(bool(self.config.get('batch_rbf', False)))
        batch_rbf_cb.setEnabled(use_rbf)
        batch_rbf_cb.setToolTip(
            _('If you check this box, your unconfirmed transactions will be consolidated into a single transaction.') + '\n' + \
            _('This will save fees.'))
        def on_batch_rbf(x):
            self.config.set_key('batch_rbf', bool(x))
        batch_rbf_cb.stateChanged.connect(on_batch_rbf)
        fee_widgets.append((batch_rbf_cb, None))

        # lightning
        lightning_widgets = []
        help_persist = _("""If this option is checked, Electrum will persist as a daemon after
you close all your wallet windows. Your local watchtower will keep
running, and it will protect your channels even if your wallet is not
open. For this to work, your computer needs to be online regularly.""")
        persist_cb = QCheckBox(_("Run as daemon after the GUI is closed"))
        persist_cb.setToolTip(help_persist)
        persist_cb.setChecked(bool(self.config.get('persist_daemon', False)))
        def on_persist_checked(x):
            self.config.set_key('persist_daemon', bool(x))
        persist_cb.stateChanged.connect(on_persist_checked)
        lightning_widgets.append((persist_cb, None))

        help_remote_wt = _("""To use a remote watchtower, enter the corresponding URL here""")
        remote_wt_cb = QCheckBox(_("Use a remote watchtower"))
        remote_wt_cb.setToolTip(help_remote_wt)
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
        lightning_widgets.append((remote_wt_cb, self.watchtower_url_e))

        msg = _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n'\
              + _('The following alias providers are available:') + '\n'\
              + '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n'\
              + 'For more information, see https://openalias.org'
        alias_label = HelpLabel(_('OpenAlias') + ':', msg)
        alias = self.config.get('alias','')
        self.alias_e = QLineEdit(alias)
        self.set_alias_color()
        self.alias_e.editingFinished.connect(self.on_alias_edit)
        oa_widgets.append((alias_label, self.alias_e))

        # Services
        ssl_cert = self.config.get('ssl_certfile')
        ssl_cert_label = HelpLabel(_('SSL cert file') + ':', 'certificate file, with intermediate certificates if needed')
        self.ssl_cert_e = QPushButton(ssl_cert)
        self.ssl_cert_e.clicked.connect(self.select_ssl_certfile)
        services_widgets.append((ssl_cert_label, self.ssl_cert_e))

        ssl_privkey = self.config.get('ssl_keyfile')
        ssl_privkey_label = HelpLabel(_('SSL key file') + ':', '')
        self.ssl_privkey_e = QPushButton(ssl_privkey)
        self.ssl_privkey_e.clicked.connect(self.select_ssl_privkey)
        services_widgets.append((ssl_privkey_label, self.ssl_privkey_e))

        ssl_domain_label = HelpLabel(_('SSL domain') + ':', '')
        self.ssl_domain_e = QLineEdit('')
        self.ssl_domain_e.setReadOnly(True)
        services_widgets.append((ssl_domain_label, self.ssl_domain_e))

        self.check_ssl_config()

        hostname = self.config.get('services_hostname', 'localhost')
        hostname_label = HelpLabel(_('Hostname') + ':', 'must match your SSL domain')
        self.hostname_e = QLineEdit(hostname)
        self.hostname_e.editingFinished.connect(self.on_hostname)
        services_widgets.append((hostname_label, self.hostname_e))

        payserver_cb = QCheckBox(_("Run PayServer"))
        payserver_cb.setToolTip("Configure a port")
        payserver_cb.setChecked(bool(self.config.get('run_payserver', False)))
        def on_payserver_checked(x):
            self.config.set_key('run_payserver', bool(x))
            self.payserver_port_e.setEnabled(bool(x))
        payserver_cb.stateChanged.connect(on_payserver_checked)
        payserver_port = self.config.get('payserver_port', 8002)
        self.payserver_port_e = QLineEdit(str(payserver_port))
        self.payserver_port_e.editingFinished.connect(self.on_payserver_port)
        self.payserver_port_e.setEnabled(self.config.get('run_payserver', False))
        services_widgets.append((payserver_cb, self.payserver_port_e))

        help_local_wt = _("""To setup a local watchtower, you must run Electrum on a machine
that is always connected to the internet. Configure a port if you want it to be public.""")
        local_wt_cb = QCheckBox(_("Run Watchtower"))
        local_wt_cb.setToolTip(help_local_wt)
        local_wt_cb.setChecked(bool(self.config.get('run_watchtower', False)))
        def on_local_wt_checked(x):
            self.config.set_key('run_watchtower', bool(x))
            self.local_wt_port_e.setEnabled(bool(x))
        local_wt_cb.stateChanged.connect(on_local_wt_checked)
        watchtower_port = self.config.get('watchtower_port', '')
        self.local_wt_port_e = QLineEdit(str(watchtower_port))
        self.local_wt_port_e.setEnabled(self.config.get('run_watchtower', False))
        self.local_wt_port_e.editingFinished.connect(self.on_watchtower_port)
        services_widgets.append((local_wt_cb, self.local_wt_port_e))

        # units
        units = base_units_list
        msg = (_('Base unit of your wallet.')
               + '\n1 BTC = 1000 mBTC. 1 mBTC = 1000 bits. 1 bit = 100 sat.\n'
               + _('This setting affects the Send tab, and all balance related fields.'))
        unit_label = HelpLabel(_('Base unit') + ':', msg)
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(self.window.base_unit()))
        def on_unit(x, nz):
            unit_result = units[unit_combo.currentIndex()]
            if self.window.base_unit() == unit_result:
                return
            edits = self.window.amount_e, self.window.receive_amount_e
            amounts = [edit.get_amount() for edit in edits]
            self.window.decimal_point = base_unit_name_to_decimal_point(unit_result)
            self.config.set_key('decimal_point', self.window.decimal_point, True)
            nz.setMaximum(self.window.decimal_point)
            self.window.history_list.update()
            self.window.request_list.update()
            self.window.address_list.update()
            for edit, amount in zip(edits, amounts):
                edit.setAmount(amount)
            self.window.update_status()
        unit_combo.currentIndexChanged.connect(lambda x: on_unit(x, nz))
        gui_widgets.append((unit_label, unit_combo))

        system_cameras = qrscanner._find_system_cameras()
        qr_combo = QComboBox()
        qr_combo.addItem("Default","default")
        for camera, device in system_cameras.items():
            qr_combo.addItem(camera, device)
        #combo.addItem("Manually specify a device", config.get("video_device"))
        index = qr_combo.findData(self.config.get("video_device"))
        qr_combo.setCurrentIndex(index)
        msg = _("Install the zbar package to enable this.")
        qr_label = HelpLabel(_('Video Device') + ':', msg)
        qr_combo.setEnabled(qrscanner.libzbar is not None)
        on_video_device = lambda x: self.config.set_key("video_device", qr_combo.itemData(x), True)
        qr_combo.currentIndexChanged.connect(on_video_device)
        gui_widgets.append((qr_label, qr_combo))

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
        gui_widgets.append((colortheme_label, colortheme_combo))

        updatecheck_cb = QCheckBox(_("Automatically check for software updates"))
        updatecheck_cb.setChecked(bool(self.config.get('check_updates', False)))
        def on_set_updatecheck(v):
            self.config.set_key('check_updates', v == Qt.Checked, save=True)
        updatecheck_cb.stateChanged.connect(on_set_updatecheck)
        gui_widgets.append((updatecheck_cb, None))

        filelogging_cb = QCheckBox(_("Write logs to file"))
        filelogging_cb.setChecked(bool(self.config.get('log_to_file', False)))
        def on_set_filelogging(v):
            self.config.set_key('log_to_file', v == Qt.Checked, save=True)
            self.need_restart = True
        filelogging_cb.stateChanged.connect(on_set_filelogging)
        filelogging_cb.setToolTip(_('Debug logs can be persisted to disk. These are useful for troubleshooting.'))
        gui_widgets.append((filelogging_cb, None))

        preview_cb = QCheckBox(_('Advanced preview'))
        preview_cb.setChecked(bool(self.config.get('advanced_preview', False)))
        preview_cb.setToolTip(_("Open advanced transaction preview dialog when 'Pay' is clicked."))
        def on_preview(x):
            self.config.set_key('advanced_preview', x == Qt.Checked)
        preview_cb.stateChanged.connect(on_preview)
        tx_widgets.append((preview_cb, None))

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(self.window.wallet.use_change)
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)
        def on_usechange(x):
            usechange_result = x == Qt.Checked
            if self.window.wallet.use_change != usechange_result:
                self.window.wallet.use_change = usechange_result
                self.window.wallet.storage.put('use_change', self.window.wallet.use_change)
                multiple_cb.setEnabled(self.window.wallet.use_change)
        usechange_cb.stateChanged.connect(on_usechange)
        usechange_cb.setToolTip(_('Using change addresses makes it more difficult for other people to track your transactions.'))
        tx_widgets.append((usechange_cb, None))

        def on_multiple(x):
            multiple = x == Qt.Checked
            if self.wallet.multiple_change != multiple:
                self.wallet.multiple_change = multiple
                self.wallet.storage.put('multiple_change', multiple)
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
        tx_widgets.append((multiple_cb, None))

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
            tx_widgets.append((chooser_label, chooser_combo))

        def on_unconf(x):
            self.config.set_key('confirmed_only', bool(x))
        conf_only = bool(self.config.get('confirmed_only', False))
        unconf_cb = QCheckBox(_('Spend only confirmed coins'))
        unconf_cb.setToolTip(_('Spend only confirmed inputs.'))
        unconf_cb.setChecked(conf_only)
        unconf_cb.stateChanged.connect(on_unconf)
        tx_widgets.append((unconf_cb, None))

        def on_outrounding(x):
            self.config.set_key('coin_chooser_output_rounding', bool(x))
        enable_outrounding = bool(self.config.get('coin_chooser_output_rounding', False))
        outrounding_cb = QCheckBox(_('Enable output value rounding'))
        outrounding_cb.setToolTip(
            _('Set the value of the change output so that it has similar precision to the other outputs.') + '\n' +
            _('This might improve your privacy somewhat.') + '\n' +
            _('If enabled, at most 100 satoshis might be lost due to this, per transaction.'))
        outrounding_cb.setChecked(enable_outrounding)
        outrounding_cb.stateChanged.connect(on_outrounding)
        tx_widgets.append((outrounding_cb, None))

        block_explorers = sorted(util.block_explorer_info().keys())
        msg = _('Choose which online block explorer to use for functions that open a web browser')
        block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_ex_combo.findText(util.block_explorer(self.config)))
        def on_be(x):
            be_result = block_explorers[block_ex_combo.currentIndex()]
            self.config.set_key('block_explorer', be_result, True)
        block_ex_combo.currentIndexChanged.connect(on_be)
        tx_widgets.append((block_ex_label, block_ex_combo))

        # Fiat Currency
        hist_checkbox = QCheckBox()
        hist_capgains_checkbox = QCheckBox()
        fiat_address_checkbox = QCheckBox()
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        def update_currencies():
            if not self.window.fx: return
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
            self.window.update_fiat()

        def on_exchange(idx):
            exchange = str(ex_combo.currentText())
            if self.fx and self.fx.is_enabled() and exchange and exchange != self.fx.exchange.name():
                self.fx.set_exchange(exchange)

        def on_history(checked):
            if not self.fx: return
            self.fx.set_history_config(checked)
            update_exchanges()
            self.window.history_model.refresh('on_history')
            if self.fx.is_enabled() and checked:
                self.fx.trigger_update()
            update_history_capgains_cb()

        def on_history_capgains(checked):
            if not self.fx: return
            self.fx.set_history_capital_gains_config(checked)
            self.window.history_model.refresh('on_history_capgains')

        def on_fiat_address(checked):
            if not self.fx: return
            self.fx.set_fiat_address_config(checked)
            self.window.address_list.refresh_headers()
            self.window.address_list.update()

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

        fiat_widgets = []
        fiat_widgets.append((QLabel(_('Fiat currency')), ccy_combo))
        fiat_widgets.append((QLabel(_('Source')), ex_combo))
        fiat_widgets.append((QLabel(_('Show history rates')), hist_checkbox))
        fiat_widgets.append((QLabel(_('Show capital gains in history')), hist_capgains_checkbox))
        fiat_widgets.append((QLabel(_('Show Fiat balance for addresses')), fiat_address_checkbox))

        tabs_info = [
            (gui_widgets, _('General')),
            (fee_widgets, _('Fees')),
            (tx_widgets, _('Transactions')),
            (lightning_widgets, _('Lightning')),
            (fiat_widgets, _('Fiat')),
            (services_widgets, _('Services')),
            (oa_widgets, _('OpenAlias')),
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
        
    def set_alias_color(self):
        if not self.config.get('alias'):
            self.alias_e.setStyleSheet("")
            return
        if self.window.alias_info:
            alias_addr, alias_name, validated = self.window.alias_info
            self.alias_e.setStyleSheet((ColorScheme.GREEN if validated else ColorScheme.RED).as_stylesheet(True))
        else:
            self.alias_e.setStyleSheet(ColorScheme.RED.as_stylesheet(True))

    def on_alias_edit(self):
        self.alias_e.setStyleSheet("")
        alias = str(self.alias_e.text())
        self.config.set_key('alias', alias, True)
        if alias:
            self.window.fetch_alias()

    def select_ssl_certfile(self, b):
        name = self.config.get('ssl_certfile', '')
        filename, __ = QFileDialog.getOpenFileName(self, "Select your SSL certificate file", name)
        if filename:
            self.config.set_key('ssl_certfile', filename)
            self.ssl_cert_e.setText(filename)
            self.check_ssl_config()

    def select_ssl_privkey(self, b):
        name = self.config.get('ssl_keyfile', '')
        filename, __ = QFileDialog.getOpenFileName(self, "Select your SSL private key file", name)
        if filename:
            self.config.set_key('ssl_keyfile', filename)
            self.ssl_cert_e.setText(filename)
            self.check_ssl_config()

    def check_ssl_config(self):
        if self.config.get('ssl_keyfile') and self.config.get('ssl_certfile'):
            try:
                SSL_identity = paymentrequest.check_ssl_config(self.config)
                SSL_error = None
            except BaseException as e:
                SSL_identity = "error"
                SSL_error = repr(e)
        else:
            SSL_identity = ""
            SSL_error = None
        self.ssl_domain_e.setText(SSL_identity)
        s = (ColorScheme.RED if SSL_error else ColorScheme.GREEN).as_stylesheet(True) if SSL_identity else ''
        self.ssl_domain_e.setStyleSheet(s)
        if SSL_error:
            self.ssl_domain_e.setText(SSL_error)

    def on_hostname(self):
        hostname = str(self.hostname_e.text())
        self.config.set_key('services_hostname', hostname, True)

    def _get_int_port_from_port_text(self, port_text) -> Optional[int]:
        if not port_text:
            return
        try:
            port = int(port_text)
            if not (0 < port < 2 ** 16):
                raise Exception('port out of range')
        except Exception:
            self.window.show_error("invalid port")
            return
        return port

    def on_payserver_port(self):
        port_text = self.payserver_port_e.text()
        port = self._get_int_port_from_port_text(port_text)
        if port is None: return
        self.config.set_key('payserver_port', port, True)

    def on_watchtower_port(self):
        port_text = self.payserver_port_e.text()
        port = self._get_int_port_from_port_text(port_text)
        if port is None: return
        self.config.set_key('watchtower_port', port, True)
