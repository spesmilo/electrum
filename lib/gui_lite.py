from PyQt4.QtCore import *
from PyQt4.QtGui import *
from decimal import Decimal as D
from i18n import _
import exchange_rate
import random
import re
import sys
import time
import wallet

try:
    import lib.gui_qt as gui_qt
except ImportError:
    import electrum.gui_qt as gui_qt

bitcoin = lambda v: v * 100000000

def IconButton(filename, parent=None):
    pixmap = QPixmap(filename)
    icon = QIcon(pixmap)
    return QPushButton(icon, "", parent)

class Timer(QThread):
    def run(self):
        while True:
            self.emit(SIGNAL('timersignal'))
            time.sleep(0.5)

class ElectrumGui:

    def __init__(self, wallet):
        self.wallet = wallet
        self.app = QApplication(sys.argv)
        with open("data/style.css") as style_file:
            self.app.setStyleSheet(style_file.read())

    def main(self, url):
        actuator = MiniActuator(self.wallet)
        self.mini = MiniWindow(actuator, self.expand)
        driver = MiniDriver(self.wallet, self.mini)

        timer = Timer()
        timer.start()
        self.expert = gui_qt.ElectrumWindow(self.wallet)
        self.expert.connect_slots(timer)
        self.expert.update_wallet()

        sys.exit(self.app.exec_())

    def expand(self):
        self.mini.hide()
        self.expert.show()

class MiniWindow(QDialog):

    def __init__(self, actuator, expand_callback):
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
        self.connect(expand_button, SIGNAL("clicked()"), expand_callback)

        self.btc_balance = 0
        self.quote_currencies = ("EUR", "USD", "GBP")
        self.exchanger = exchange_rate.Exchanger(self.quote_currencies)

        self.balance_label = BalanceLabel(self.change_quote_currency)
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
        self.amount_validator.setDecimals(8)
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

    def change_quote_currency(self):
        self.quote_currencies = \
            self.quote_currencies[1:] + self.quote_currencies[0:1]
        self.set_balances(self.btc_balance)

    def set_balances(self, btc_balance):
        self.btc_balance = btc_balance
        btc_balance /= bitcoin(1)
        quote_balance = "%.2f" % (btc_balance * 6)
        quote_currency = self.quote_currencies[0]
        self.balance_label.set_balances( \
            btc_balance, quote_balance, quote_currency)
        main_account_info = \
            "Checking - %s BTC (%s %s)" % (btc_balance,
                                           quote_balance, quote_currency)
        self.setWindowTitle("Electrum - %s" % main_account_info)
        self.accounts_selector.clear()
        self.accounts_selector.addAction("%s" % main_account_info)

    def send(self):
        if self.actuator.send(self.address_input.text(),
                              self.amount_input.text(), self):
            self.address_input.become_inactive()
            self.amount_input.become_inactive()

    def address_field_changed(self, address):
        if self.actuator.is_valid(address):
            self.valid_address.setChecked(True)
        else:
            self.valid_address.setChecked(False)

    def show_about(self):
        QMessageBox.about(self, "Electrum",
            _("Electrum's focus is speed, with low resource usage and simplifying Bitcoin. You do not need to perform regular backups, because your wallet can be recovered from a secret phrase that you can memorize or write on paper. Startup times are instant because it operates in conjuction with high-performance servers that handle the most complicated parts of the Bitcoin system."))

    def show_report_bug(self):
        QMessageBox.information(self, "Electrum - " + _("Reporting Bugs"),
            _("Email bug reports to %s") % "genjix" + "@" + "riseup.net")

class BalanceLabel(QLabel):

    def __init__(self, change_quote_currency, parent=None):
        super(QLabel, self).__init__(_("Connecting..."), parent)
        self.change_quote_currency = change_quote_currency

    def set_balances(self, btc_balance, quote_balance, quote_currency):
        label_text = "<span style='font-size: 16pt'>%s</span> <span style='font-size: 10pt'>BTC</span> <span style='font-size: 10pt'>(%s %s)</span>" % (btc_balance, quote_balance, quote_currency)
        self.setText(label_text)

    def mousePressEvent(self, event):
        self.change_quote_currency()

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

def ok_cancel_buttons(dialog):
    row_layout = QHBoxLayout()
    row_layout.addStretch(1)
    ok_button = QPushButton("OK")
    row_layout.addWidget(ok_button)
    ok_button.clicked.connect(dialog.accept)
    cancel_button = QPushButton("Cancel")
    row_layout.addWidget(cancel_button)
    cancel_button.clicked.connect(dialog.reject)
    return row_layout

class PasswordDialog(QDialog):

    def __init__(self, parent):
        super(QDialog, self).__init__(parent)

        self.setModal(True)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        main_layout = QVBoxLayout(self)
        message = _('Please enter your password')
        main_layout.addWidget(QLabel(message))

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(QLabel(_('Password')), 1, 0)
        grid.addWidget(self.password_input, 1, 1)
        main_layout.addLayout(grid)

        main_layout.addLayout(ok_cancel_buttons(self))
        self.setLayout(main_layout) 

    def run(self):
        if not self.exec_():
            return
        return unicode(self.password_input.text())

class MiniActuator:

    def __init__(self, wallet):
        self.wallet = wallet

    def copy_address(self):
        addrs = [addr for addr in self.wallet.all_addresses()
                 if not self.wallet.is_change(addr)]
        qApp.clipboard().setText(random.choice(addrs))

    def send(self, address, amount, parent_window):
        dest_address = self.fetch_destination(address)

        if dest_address is None or not self.wallet.is_valid(dest_address):
            QMessageBox.warning(parent_window, _('Error'), 
                _('Invalid Bitcoin Address') + ':\n' + address, _('OK'))
            return False

        convert_amount = lambda amount: \
            int(D(unicode(amount)) * bitcoin(1))
        amount = convert_amount(amount)

        if self.wallet.use_encryption:
            password_dialog = PasswordDialog(parent_window)
            password = password_dialog.run()
            if not password:
                return
        else:
            password = None

        fee = 0
        # 0.1 BTC = 10000000
        if amount < bitcoin(1) / 10:
            # 0.01 BTC
            fee = bitcoin(1) / 100

        try:
            tx = self.wallet.mktx(dest_address, amount, "", password, fee)
        except BaseException as error:
            QMessageBox.warning(parent_window, _('Error'), str(error), _('OK'))
            return False
            
        status, message = self.wallet.sendtx(tx)
        if not status:
            QMessageBox.warning(parent_window, _('Error'), message, _('OK'))
            return False

        QMessageBox.information(parent_window, '',
            _('Payment sent.') + '\n' + message, _('OK'))
        return True

    def fetch_destination(self, address):
        recipient = unicode(address).strip()

        # alias
        match1 = re.match("^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$",
                          recipient)

        # label or alias, with address in brackets
        match2 = re.match("(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>",
                          recipient)
        
        if match1:
            dest_address = \
                self.wallet.get_alias(recipient, True, 
                                      self.show_message, self.question)
            return dest_address
        elif match2:
            return match2.group(2)
        else:
            return recipient

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

        self.wallet.register_callback(self.update_callback)

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
        balance = D(conf_balance + unconf_balance)
        self.window.set_balances(balance)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    with open("data/style.css") as style_file:
        app.setStyleSheet(style_file.read())
    mini = MiniWindow()
    sys.exit(app.exec_())

