from PyQt4.QtCore import *
from PyQt4.QtGui import *
from i18n import _
import decimal
import random
import re
import sys

def IconButton(filename, parent=None):
    pixmap = QPixmap(filename)
    icon = QIcon(pixmap)
    return QPushButton(icon, "", parent)

class ElectrumGui:

    def __init__(self, wallet):
        self.wallet = wallet
        self.app = QApplication(sys.argv)
        with open("data/style.css") as style_file:
            self.app.setStyleSheet(style_file.read())

    def main(self, url):
        actuator = MiniActuator(self.wallet)
        mini = MiniWindow(actuator)
        driver = MiniDriver(self.wallet, mini)
        sys.exit(self.app.exec_())

class MiniWindow(QDialog):

    def __init__(self, actuator):
        super(MiniWindow, self).__init__()

        self.actuator = actuator

        accounts_button = IconButton("data/icons/accounts.png")
        accounts_button.setObjectName("accounts_button")

        self.accounts_selector = QMenu()
        accounts_button.setMenu(self.accounts_selector)

        interact_button = IconButton("data/icons/interact.png")
        interact_button.setObjectName("interact_button")

        app_menu = QMenu()
        report_action = app_menu.addAction(_("&Report Bug"))
        about_action = app_menu.addAction(_("&About Electrum"))
        app_menu.addSeparator()
        quit_action = app_menu.addAction(_("&Quit"))
        interact_button.setMenu(app_menu)

        self.connect(report_action, SIGNAL("triggered()"),
                     self.show_report_bug)
        self.connect(about_action, SIGNAL("triggered()"), self.show_about)
        self.connect(quit_action, SIGNAL("triggered()"), self.close)

        expand_button = IconButton("data/icons/expand.png")
        expand_button.setObjectName("expand_button")

        self.balance_label = BalanceLabel()
        self.balance_label.setObjectName("balance_label")

        copy_button = QPushButton(_("&Copy Address"))
        copy_button.setObjectName("copy_button")
        copy_button.setDefault(True)
        self.connect(copy_button, SIGNAL("clicked()"),
                     self.actuator.copy_address)

        # Use QCompleter
        self.address_input = TextedLineEdit(_("Enter a Bitcoin address..."))
        self.address_input.setObjectName("address_input")
        self.connect(self.address_input, SIGNAL("textChanged(QString)"),
                     self.address_field_changed)
        metrics = QFontMetrics(qApp.font())
        self.address_input.setMinimumWidth(
            metrics.width("1E4vM9q25xsyDwWwdqHUWnwshdWC9PykmL"))

        self.valid_address = QCheckBox()
        self.valid_address.setObjectName("valid_address")
        self.valid_address.setEnabled(False)
        self.valid_address.setChecked(False)

        address_layout = QHBoxLayout()
        address_layout.addWidget(self.address_input)
        address_layout.addWidget(self.valid_address)

        self.amount_input = TextedLineEdit(_("... and amount"))
        self.amount_input.setObjectName("amount_input")
        # This is changed according to the user's displayed balance
        self.amount_validator = QDoubleValidator(self.amount_input)
        self.amount_validator.setNotation(QDoubleValidator.StandardNotation)
        self.amount_validator.setRange(0, 0)
        self.amount_validator.setDecimals(2)
        self.amount_input.setValidator(self.amount_validator)

        amount_layout = QHBoxLayout()
        amount_layout.addWidget(self.amount_input)
        amount_layout.addStretch()

        send_button = QPushButton(_("&Send"))
        send_button.setObjectName("send_button")
        self.connect(send_button, SIGNAL("clicked()"), self.send)

        main_layout = QGridLayout(self)
        main_layout.addWidget(accounts_button, 0, 0)
        main_layout.addWidget(interact_button, 1, 0)
        main_layout.addWidget(expand_button, 2, 0)

        main_layout.addWidget(self.balance_label, 0, 1)
        main_layout.addWidget(copy_button, 0, 2)

        main_layout.addLayout(address_layout, 1, 1, 1, -1)

        main_layout.addLayout(amount_layout, 2, 1)
        main_layout.addWidget(send_button, 2, 2)

        self.setWindowTitle("Electrum")
        self.setWindowFlags(Qt.Window|Qt.MSWindowsFixedSizeDialogHint)
        self.layout().setSizeConstraint(QLayout.SetFixedSize)
        self.setObjectName("main_window")
        self.show()

    def closeEvent(self, event):
        super(MiniWindow, self).closeEvent(event)
        qApp.quit()

    def activate(self):
        pass

    def deactivate(self):
        pass

    def set_balances(self, btc_balance, quote_balance, quote_currency):
        self.balance_label.set_balances( \
            btc_balance, quote_balance, quote_currency)
        self.amount_validator.setRange(0, btc_balance)
        main_account_info = \
            "Checking - %s BTC (%s %s)" % (btc_balance,
                                           quote_balance, quote_currency)
        self.setWindowTitle("Electrum - %s" % main_account_info)
        self.accounts_selector.clear()
        self.accounts_selector.addAction("%s" % main_account_info)

    def send(self):
        self.actuator.send(self.address_input.text(),
                           self.amount_input.text(), self)

    def address_field_changed(self, address):
        if self.actuator.is_valid(address):
            self.valid_address.setChecked(True)
        else:
            self.valid_address.setChecked(False)

    def show_about(self):
        QMessageBox.about(self, "Electrum",
            "Electrum's focus is speed, with low resource usage and simplifying Bitcoin. You do not need to perform regular backups, because your wallet can be recovered from a secret phrase that you can memorize or write on paper. Startup times are instant because it operates in conjuction with high-performance servers that handle the most complicated parts of the Bitcoin system.")

    def show_report_bug(self):
        QMessageBox.information(self, "Electrum - Reporting Bugs",
            "Email bug reports to %s@%s.net" % ("genjix", "riseup"))

class BalanceLabel(QLabel):

    def __init__(self, parent=None):
        super(QLabel, self).__init__("Connecting...", parent)

    def set_balances(self, btc_balance, quote_balance, quote_currency):
        label_text = "<span style='font-size: 16pt'>%s</span> <span style='font-size: 10pt'>BTC</span> <span style='font-size: 10pt'>(%s %s)</span>" % (btc_balance, quote_balance, quote_currency)
        self.setText(label_text)

class TextedLineEdit(QLineEdit):

    def __init__(self, inactive_text, parent=None):
        super(QLineEdit, self).__init__(parent)
        self.inactive_text = inactive_text
        self.become_inactive()

    def mousePressEvent(self, event):
        if self.isReadOnly():
            self.become_active()
        QLineEdit.mousePressEvent(self, event)

    def focusOutEvent(self, event):
        if self.text() == "":
            self.become_inactive()
        QLineEdit.focusOutEvent(self, event)

    def focusInEvent(self, event):
        if self.isReadOnly():
            self.become_active()
        QLineEdit.focusInEvent(self, event)

    def become_inactive(self):
        self.setText(self.inactive_text)
        self.setReadOnly(True)
        self.recompute_style()

    def become_active(self):
        self.setText("")
        self.setReadOnly(False)
        self.recompute_style()

    def recompute_style(self):
        qApp.style().unpolish(self)
        qApp.style().polish(self)
        # also possible but more expensive:
        #qApp.setStyleSheet(qApp.styleSheet())

class MiniActuator:

    def __init__(self, wallet):
        self.wallet = wallet

    def copy_address(self):
        addrs = [addr for addr in self.wallet.all_addresses()
                 if not self.wallet.is_change(addr)]
        qApp.clipboard().setText(random.choice(addrs))

    def send(self, address, amount, parent_window):
        recipient = unicode(address).strip()

        # alias
        match1 = re.match(ALIAS_REGEXP, r)
        # label or alias, with address in brackets
        match2 = re.match('(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>', r)
        
        if match1:
            dest_address = \
                self.wallet.get_alias(recipient, True, 
                                      self.show_message, self.question)
            if not dest_address:
                return
        elif match2:
            dest_address = match2.group(2)
        else:
            dest_address = recipient

        if not self.wallet.is_valid(dest_address):
            QMessageBox.warning(parent_window, _('Error'), 
                _('Invalid Bitcoin Address') + ':\n' + dest_address, _('OK'))
            return

        convert_amount = lambda amount: \
            int(decimal.Decimal(unicode(amount)) * 100000000)

        amount = convert_amount(amount)

        if self.wallet.use_encryption:
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None

        try:
            tx = self.wallet.mktx(dest_address, amount, "", password, fee)
        except BaseException, e:
            self.show_message(str(e))
            return
            
        status, msg = self.wallet.sendtx( tx )
        if status:
            QMessageBox.information(self, '', _('Payment sent.')+'\n'+msg, _('OK'))
            self.do_clear()
            self.update_contacts_tab()
        else:
            QMessageBox.warning(self, _('Error'), msg, _('OK'))

    def is_valid(self, address):
        return self.wallet.is_valid(address)

class MiniDriver(QObject):

    INITIALIZING = 0
    CONNECTING = 1
    SYNCHRONIZING = 2
    READY = 3

    def __init__(self, wallet, window):
        super(QObject, self).__init__()

        self.wallet = wallet
        self.window = window

        self.wallet.gui_callback = self.update_callback

        self.state = None

        self.initializing()
        self.connect(self, SIGNAL("updatesignal()"), self.update)

    # This is a hack to workaround that Qt does not like changing the
    # window properties from this other thread before the runloop has
    # been called from.
    def update_callback(self):
        self.emit(SIGNAL("updatesignal()"))

    def update(self):
        if not self.wallet.interface:
            self.initializing()
        elif not self.wallet.interface.is_connected:
            self.connecting()
        elif not self.wallet.blocks == -1:
            self.connecting()
        elif not self.wallet.is_up_to_date:
            self.synchronizing()
        else:
            self.ready()

        if self.wallet.up_to_date:
            self.update_balance()

    def initializing(self):
        if self.state == self.INITIALIZING:
            return
        self.state = self.INITIALIZING
        self.window.deactivate()

    def connecting(self):
        if self.state == self.CONNECTING:
            return
        self.state = self.CONNECTING
        self.window.deactivate()

    def synchronizing(self):
        if self.state == self.SYNCHRONIZING:
            return
        self.state = self.SYNCHRONIZING
        self.window.deactivate()

    def ready(self):
        if self.state == self.READY:
            return
        self.state = self.READY
        self.window.activate()

    def update_balance(self):
        conf_balance, unconf_balance = self.wallet.get_balance()
        balance = conf_balance if unconf_balance is None else unconf_balance
        self.window.set_balances(balance, balance * 6, 'EUR')

if __name__ == "__main__":
    app = QApplication(sys.argv)
    with open("data/style.css") as style_file:
        app.setStyleSheet(style_file.read())
    mini = MiniWindow()
    sys.exit(app.exec_())

