#!/usr/bin/env python3
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
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

import time
import threading
import queue
import base64
from functools import partial

import smtplib
import imaplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.encoders import encode_base64

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.plugins import BasePlugin, hook
from electroncash.paymentrequest import PaymentRequest
from electroncash.i18n import _
from electroncash_gui.qt.util import EnterButton, Buttons, CloseButton
from electroncash_gui.qt.util import OkButton, WindowModalDialog
from electroncash.util import Weak, PrintError


class Processor(threading.Thread, PrintError):
    polling_interval = 5*60

    instance = None

    def __init__(self, imap_server, username, password, callback, error_callback):
        threading.Thread.__init__(self)
        Processor.instance = self
        self.daemon = True
        self.username = username
        self.password = password
        self.imap_server = imap_server
        self.on_receive = callback
        self.on_error = error_callback
        self.q = queue.Queue()

    def diagnostic_name(self): return "Email.Processor"

    def poll(self):
        try:
            self.M.select()
        except:
            return
        typ, data = self.M.search(None, 'ALL')
        for num in data[0].split():
            typ, msg_data = self.M.fetch(num, '(RFC822)')
            if type(msg_data[0][1]) is bytes:
                msg = email.message_from_bytes(msg_data[0][1])
            else:
                msg = email.message_from_string(msg_data[0][1])
            p = msg.get_payload()
            if not msg.is_multipart():
                p = [p]
                continue
            for item in p:
                if item.get_content_type() == "application/bitcoin-paymentrequest":
                    pr_str = item.get_payload()
                    pr_str = base64.b64decode(pr_str)
                    self.on_receive(pr_str)

    def run(self):
        try:
            self.M = imaplib.IMAP4_SSL(self.imap_server)
            self.M.login(self.username, self.password)
        except Exception as e:
            self.print_error("Exception encountered, stopping plugin thread:", repr(e))
            self.on_error(_("Email plugin could not connect to {server} as {username}, IMAP receive thread stopped.").format(server=self.imap_server, username=self.username))
            return
        try:
            while Processor.instance is self:
                self.poll()
                try:
                    self.q.get(timeout=self.polling_interval)  # sleep for polling_interval seconds
                    return # if we get here, we were stopped
                except queue.Empty:
                    ''' If we get here, we slept for polling_interval seconds '''
            self.M.close()
            self.M.logout()
        except Exception as e:
            self.print_error("Exception encountered, stopping plugin thread:", repr(e))
            self.on_error(_("Email plugin encountered an error, plugin stopped."))

    def send(self, recipient, message, payment_request):
        msg = MIMEMultipart()
        msg['Subject'] = message
        msg['To'] = recipient
        msg['From'] = self.username
        part = MIMEBase('application', "bitcoin-paymentrequest")
        part.set_payload(payment_request)
        encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="payreq.btc"')
        msg.attach(part)
        s = smtplib.SMTP_SSL(self.imap_server, timeout=2)
        s.login(self.username, self.password)
        s.sendmail(self.username, [recipient], msg.as_string())
        s.quit()


class EmailSignalObject(QObject):
    email_new_invoice_signal = pyqtSignal()
    email_error = pyqtSignal(str)


class Plugin(BasePlugin):

    def fullname(self):
        return 'Email'

    def description(self):
        return _("Send and receive payment requests via email")

    def is_available(self):
        return True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.imap_server = self.config.get('email_server', '')
        self.username = self.config.get('email_username', '')
        self.password = self.config.get('email_password', '')
        if self.imap_server and self.username and self.password:
            self.processor = Processor(self.imap_server, self.username, self.password, self.on_receive, self.on_error)
            self.processor.start()
        else:
            self.processor = None
        self.obj = EmailSignalObject()
        self.obj.email_new_invoice_signal.connect(self.new_invoice)
        self.obj.email_error.connect(self.on_error_qt)

    def on_close(self):
        ''' called on plugin close '''
        Processor.instance = None  # tells thread that it is defunct
        if self.processor and self.processor.is_alive():
            self.processor.q.put(None)  # signal stop
            self.processor.join(timeout=1.0)

    def on_receive(self, pr_str):
        self.print_error('received payment request')
        self.pr = PaymentRequest(pr_str)
        self.obj.email_new_invoice_signal.emit()

    def on_error(self, err):
        self.obj.email_error.emit(err)

    def on_error_qt(self, err):
        QMessageBox.warning(None, _("Email Error"), err)

    def new_invoice(self):
        self.parent.invoices.add(self.pr)
        #window.update_invoices_list()

    @hook
    def receive_list_menu(self, menu, addr):
        window = menu.parentWidget().parent  # Grr. Electrum programmers overwrote parent() method.
        menu.addAction(_("Send via e-mail"), lambda: self.send(window, addr))

    def send(self, window, addr):
        if not self.processor:
            window.show_warning(_('The email plugin is enabled but not configured. Please go to its settings and configure it, or disable it if you do not wish to use it.'))
            return
        from electroncash import paymentrequest
        r = window.wallet.receive_requests.get(addr)
        message = r.get('memo', '')
        try:
            if r.get('signature'):
                pr = paymentrequest.serialize_request(r)
            else:
                pr = paymentrequest.make_request(self.config, r)
        except ValueError as e:
            ''' Bad data such as out-of-range amount, see #1738 '''
            self.print_error('Error serializing request:', repr(e))
            window.show_error(str(e))
            return
        if not pr:
            return
        recipient, ok = QInputDialog.getText(window, _('Send request'), _('Email invoice to:'))
        if not ok:
            return
        recipient = str(recipient)
        payload = pr.SerializeToString()
        self.print_error('sending mail to', recipient)
        try:
            self.processor.send(recipient, message, payload)
        except Exception as e:
            self.print_error("Exception sending:", repr(e))
            # NB; we don't want to actually display the exception message here
            # because it may contain text from the server, which could be a
            # potential phishing attack surface.  So instead we show the user
            # the exception name which is something like ConnectionRefusedError.
            window.show_error(_("Could not send email to {recipient}: {reason}").format(recipient=recipient, reason=type(e).__name__))
            return

        window.show_message(_('Request sent.'))


    def requires_settings(self):
        return True

    def settings_widget(self, window):
        windowRef = Weak.ref(window)
        return EnterButton(_('Settings'), partial(self.settings_dialog, windowRef))

    def settings_dialog(self, windowRef):
        window = windowRef()
        if not window: return
        d = WindowModalDialog(window.top_level_window(), _("Email settings"))
        d.setMinimumSize(500, 200)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('Server hosting your email account')))
        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel('Server (IMAP)'), 0, 0)
        server_e = QLineEdit()
        server_e.setText(self.imap_server)
        grid.addWidget(server_e, 0, 1)

        grid.addWidget(QLabel('Username'), 1, 0)
        username_e = QLineEdit()
        username_e.setText(self.username)
        grid.addWidget(username_e, 1, 1)

        grid.addWidget(QLabel('Password'), 2, 0)
        password_e = QLineEdit()
        password_e.setText(self.password)
        grid.addWidget(password_e, 2, 1)

        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))

        if not d.exec_():
            return

        server = str(server_e.text())
        self.config.set_key('email_server', server)

        username = str(username_e.text())
        self.config.set_key('email_username', username)

        password = str(password_e.text())
        self.config.set_key('email_password', password)
        window.show_message(_('Please restart the plugin to activate the new settings'))
