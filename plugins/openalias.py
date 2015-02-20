# Copyright (c) 2014-2015, The Monero Project
# 
# All rights reserved.

# This plugin is licensed under the GPL v3 license (see the LICENSE file in the base of
# the project source code). The Monero Project reserves the right to change this license
# in future to match or be compliant with any relicense of the Electrum project.

# This plugin implements the OpenAlias standard. For information on the standard please
# see: https://openalias.org

# Donations for ongoing development of the standard and hosting resolvers can be sent to
# openalias.org or donate.monero.cc

# Version: 0.1
# Todo: optionally use OA resolvers; add DNSCrypt support

from electrum_gui.qt.util import EnterButton
from electrum.plugins import BasePlugin, hook
from electrum.util import print_msg
from electrum.i18n import _
from PyQt4.QtGui import *
from PyQt4.QtCore import *

import re

# Import all of the rdtypes, as py2app and similar get confused with the dnspython
# autoloader and won't include all the rdatatypes
try:
    import dns.name
    import dns.query
    import dns.dnssec
    import dns.message
    import dns.resolver
    import dns.rdatatype
    import dns.rdtypes.ANY.NS
    import dns.rdtypes.ANY.CNAME
    import dns.rdtypes.ANY.DLV
    import dns.rdtypes.ANY.DNSKEY
    import dns.rdtypes.ANY.DS
    import dns.rdtypes.ANY.NSEC
    import dns.rdtypes.ANY.NSEC3
    import dns.rdtypes.ANY.NSEC3PARAM
    import dns.rdtypes.ANY.RRSIG
    import dns.rdtypes.ANY.SOA
    import dns.rdtypes.ANY.TXT
    import dns.rdtypes.IN.A
    import dns.rdtypes.IN.AAAA
    from dns.exception import DNSException
    OA_READY = True
except ImportError:
    OA_READY = False


class Plugin(BasePlugin):
    def fullname(self):
        return 'OpenAlias'

    def description(self):
        return 'Allow for payments to OpenAlias addresses.'

    def is_available(self):
        return OA_READY

    def __init__(self, gui, name):
        print_msg('[OA] Initialiasing OpenAlias plugin, OA_READY is ' + str(OA_READY))
        BasePlugin.__init__(self, gui, name)
        self._is_available = OA_READY

    @hook
    def init_qt(self, gui):
        self.gui = gui
        self.win = gui.main_window

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    @hook
    def timer_actions(self):
        if self.win.payto_e.hasFocus():
            return
        if self.win.payto_e.is_multiline():  # only supports single line entries atm
            return

        url = str(self.win.payto_e.toPlainText())
        url = url.replace('@', '.')  # support email-style addresses, per the OA standard

        if url == self.win.previous_payto_e:
            return
        self.win.previous_payto_e = url

        if ('.' in url) and (not '<' in url) and (not ' ' in url):
            if not OA_READY:  # handle a failed DNSPython load
                QMessageBox.warning(self.win, _('Error'), 'Could not load DNSPython libraries, please ensure they are available and/or Electrum has been built correctly', _('OK'))
                return
        else:
            return

        data = self.resolve(url)

        if not data:
            self.win.previous_payto_e = url
            return True

        (address, name) = data
        new_url = url + ' <' + address + '>'
        self.win.payto_e.setText(new_url)
        self.win.previous_payto_e = new_url

    @hook
    def before_send(self):
        '''
        Change URL to address before making a send.
        IMPORTANT:
            return False to continue execution of the send
            return True to stop execution of the send
        '''

        if self.win.payto_e.is_multiline():  # only supports single line entries atm
            return False
        payto_e = str(self.win.payto_e.toPlainText())
        regex = re.compile(r'^([^\s]+) <([A-Za-z0-9]+)>')  # only do that for converted addresses
        try:
            (url, address) = regex.search(payto_e).groups()
        except AttributeError:
            return False

        if not OA_READY:  # handle a failed DNSPython load
            QMessageBox.warning(self.win, _('Error'), 'Could not load DNSPython libraries, please ensure they are available and/or Electrum has been built correctly', _('OK'))
            return True

        if not self.validate_dnssec(url):
            msgBox = QMessageBox()
            msgBox.setText(_('WARNING: the address ' + address + ' could not be validated via an additional security check, DNSSEC, and thus may not be correct.'))
            msgBox.setInformativeText(_('Do you wish to continue?'))
            msgBox.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
            msgBox.setDefaultButton(QMessageBox.Cancel)
            reply = msgBox.exec_()
            if reply != QMessageBox.Ok:
                return True

        if self.config.get('openalias_autoadd') == 'checked':
            self.win.wallet.add_contact(address, name)
        return False

    def settings_dialog(self):
        '''Settings dialog.'''
        d = QDialog()
        d.setWindowTitle("Settings")
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Automatically add to contacts')), 0, 0)
        autoadd_checkbox = QCheckBox()
        autoadd_checkbox.setEnabled(True)
        autoadd_checkbox.setChecked(self.config.get('openalias_autoadd', 'unchecked') != 'unchecked')
        layout.addWidget(autoadd_checkbox, 0, 1)
        ok_button = QPushButton(_("OK"))
        ok_button.clicked.connect(d.accept)
        layout.addWidget(ok_button, 1, 1)

        def on_change_autoadd(checked):
            if checked:
                self.config.set_key('openalias_autoadd', 'checked')
            else:
                self.config.set_key('openalias_autoadd', 'unchecked')

        autoadd_checkbox.stateChanged.connect(on_change_autoadd)

        return bool(d.exec_())

    def openalias_contact_dialog(self):
        '''Previous version using a get contact button from settings, currently unused.'''
        d = QDialog(self.win)
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('Openalias Contact') + ':'))

        grid = QGridLayout()
        line1 = QLineEdit()
        grid.addWidget(QLabel(_("URL")), 1, 0)
        grid.addWidget(line1, 1, 1)

        vbox.addLayout(grid)
        vbox.addLayout(ok_cancel_buttons(d))

        if not d.exec_():
            return

        url = str(line1.text())

        url = url.replace('@', '.')

        if not '.' in url:
            QMessageBox.warning(self.win, _('Error'), _('Invalid URL'), _('OK'))
            return

        data = self.resolve(url)

        if not data:
            return

        (address, name) = data

        if not self.validate_dnssec(url):
            msgBox = QMessageBox()
            msgBox.setText(_('WARNING: the address ' + address + ' could not be validated via an additional security check, DNSSEC, and thus may not be correct.'))
            msgBox.setInformativeText("Do you wish to continue?")
            msgBox.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
            msgBox.setDefaultButton(QMessageBox.Cancel)
            reply = msgBox.exec_()
            if reply != QMessageBox.Ok:
                return

        d2 = QDialog(self.win)
        vbox2 = QVBoxLayout(d2)
        grid2 = QGridLayout()
        grid2.addWidget(QLabel(url), 1, 1)
        if name:
            grid2.addWidget(QLabel('Name: '), 2, 0)
            grid2.addWidget(QLabel(name), 2, 1)

        grid2.addWidget(QLabel('Address: '), 4, 0)
        grid2.addWidget(QLabel(address), 4, 1)

        vbox2.addLayout(grid2)
        vbox2.addLayout(ok_cancel_buttons(d2))

        if not d2.exec_():
            return

        self.win.wallet.add_contact(address)

        try:
            label = url + " (" + name + ")"
        except Exception:
            pass

        if label:
            self.win.wallet.set_label(address, label)

        self.win.update_contacts_tab()
        self.win.update_history_tab()
        self.win.update_completions()
        self.win.tabs.setCurrentIndex(3)

    def resolve(self, url):
        '''Resolve OpenAlias address using url.'''
        print_msg('[OA] Attempting to resolve OpenAlias data for ' + url)

        prefix = 'btc'
        retries = 3
        err = None
        for i in range(0, retries):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 2.0
                records = resolver.query(url, dns.rdatatype.TXT)
                for record in records:
                    string = record.strings[0]
                    if string.startswith('oa1:' + prefix):
                        address = self.find_regex(string, r'recipient_address=([A-Za-z0-9]+)')
                        name = self.find_regex(string, r'recipient_name=([^;]+)')
                        if not name:
                            name = address
                        if not address:
                            continue
                        return (address, name)
                QMessageBox.warning(self.win, _('Error'), _('No OpenAlias record found.'), _('OK'))
                return 0
            except dns.resolver.NXDOMAIN:
                err = _('No such domain.')
                continue
            except dns.resolver.Timeout:
                err = _('Timed out while resolving.')
                continue
            except DNSException:
                err = _('Unhandled exception.')
                continue
            except Exception, e:
                err = _('Unexpected error: ' + str(e))
                continue
            break
        if err:
            QMessageBox.warning(self.win, _('Error'), err, _('OK'))
        return 0

    def find_regex(self, haystack, needle):
        regex = re.compile(needle)
        try:
            return regex.search(haystack).groups()[0]
        except AttributeError:
            return None

    def validate_dnssec(self, url):
        print_msg('[OA] Checking DNSSEC trust chain for ' + url)

        try:
            default = dns.resolver.get_default_resolver()
            ns = default.nameservers[0]

            parts = url.split('.')

            for i in xrange(len(parts), 0, -1):
                sub = '.'.join(parts[i - 1:])

                query = dns.message.make_query(sub, dns.rdatatype.NS)
                response = dns.query.udp(query, ns, 1)

                if response.rcode() != dns.rcode.NOERROR:
                    return 0

                if len(response.authority) > 0:
                    rrset = response.authority[0]
                else:
                    rrset = response.answer[0]

                rr = rrset[0]
                if rr.rdtype == dns.rdatatype.SOA:
                    #Same server is authoritative, don't check again
                    continue

                query = dns.message.make_query(sub,
                                            dns.rdatatype.DNSKEY,
                                            want_dnssec=True)
                response = dns.query.udp(query, ns, 1)

                if response.rcode() != 0:
                    return 0
                    # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)

                # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
                answer = response.answer
                if len(answer) != 2:
                    return 0

                # the DNSKEY should be self signed, validate it
                name = dns.name.from_text(sub)
                try:
                    dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
                except dns.dnssec.ValidationFailure:
                    return 0
        except Exception, e:
            return 0
        return 1
