import sys

# Let's do some dep checking and handle missing ones gracefully
try:
    from PyQt4.QtCore import *
    from PyQt4.QtGui import *
    from PyQt4.Qt import Qt
    import PyQt4.QtCore as QtCore

except ImportError:
    print "You need to have PyQT installed to run Electrum-GRS in graphical mode."
    print "If you have pip installed try 'sudo pip install pyqt' if you are on Debian/Ubuntu try 'sudo apt-get install python-qt4'."
    sys.exit(0)

from decimal import Decimal as D
from electrum_grs.bitcoin import is_valid
from electrum_grs.i18n import _
import decimal
import json
import os.path
import random
import re
import time
from electrum_grs.wallet import Wallet, WalletStorage
import webbrowser
import history_widget
import receiving_widget
from electrum_grs import util
import datetime

from electrum_grs.version import ELECTRUM_VERSION as electrum_version
from electrum_grs.util import format_satoshis, age

from main_window import ElectrumWindow
import shutil

from util import *

bitcoin = lambda v: v * 100000000

def IconButton(filename, parent=None):
    pixmap = QPixmap(filename)
    icon = QIcon(pixmap)
    return QPushButton(icon, "", parent)


def resize_line_edit_width(line_edit, text_input):
    metrics = QFontMetrics(qApp.font())
    # Create an extra character to add some space on the end
    text_input += "A"
    line_edit.setMinimumWidth(metrics.width(text_input))

def load_theme_name(theme_path):
    try:
        with open(os.path.join(theme_path, "name.cfg")) as name_cfg_file:
            return name_cfg_file.read().rstrip("\n").strip()
    except IOError:
        return None


def theme_dirs_from_prefix(prefix):
    if not os.path.exists(prefix):
        return []
    theme_paths = {}
    for potential_theme in os.listdir(prefix):
        theme_full_path = os.path.join(prefix, potential_theme)
        theme_css = os.path.join(theme_full_path, "style.css")
        if not os.path.exists(theme_css):
            continue
        theme_name = load_theme_name(theme_full_path)
        if theme_name is None:
            continue
        theme_paths[theme_name] = prefix, potential_theme
    return theme_paths

def load_theme_paths():
    theme_paths = {}
    theme_dir = os.path.join(os.path.dirname(__file__), 'themes')
    theme_paths.update(theme_dirs_from_prefix(theme_dir))
    return theme_paths




class TransactionWindow(QDialog):

    def set_label(self):
        label = unicode(self.label_edit.text())
        self.parent.wallet.labels[self.tx_id] = label

        super(TransactionWindow, self).accept()

    def __init__(self, transaction_id, parent):
        super(TransactionWindow, self).__init__()

        self.tx_id = str(transaction_id)
        self.parent = parent

        self.setModal(True)
        self.resize(200,100)
        self.setWindowTitle(_("Transaction successfully sent"))

        self.layout = QGridLayout(self)
        history_label = "%s\n%s" % (_("Your transaction has been sent."), _("Please enter a label for this transaction for future reference."))
        self.layout.addWidget(QLabel(history_label))

        self.label_edit = QLineEdit()
        self.label_edit.setPlaceholderText(_("Transaction label"))
        self.label_edit.setObjectName("label_input")
        self.label_edit.setAttribute(Qt.WA_MacShowFocusRect, 0)
        self.label_edit.setFocusPolicy(Qt.ClickFocus)
        self.layout.addWidget(self.label_edit)

        self.save_button = QPushButton(_("Save"))
        self.layout.addWidget(self.save_button)
        self.save_button.clicked.connect(self.set_label)

        self.exec_()

class MiniWindow(QDialog):

    def __init__(self, actuator, expand_callback, config):
        super(MiniWindow, self).__init__()

        self.actuator = actuator
        self.config = config
        self.btc_balance = None
        self.use_exchanges = ["Blockchain", "CoinDesk"]
        self.quote_currencies = ["BRL", "CNY", "EUR", "GBP", "RUB", "USD"]
        self.actuator.set_configured_currency(self.set_quote_currency)
        self.actuator.set_configured_exchange(self.set_exchange)

        # Needed because price discovery is done in a different thread
        # which needs to be sent back to this main one to update the GUI
        self.connect(self, SIGNAL("refresh_balance()"), self.refresh_balance)

        self.balance_label = BalanceLabel(self.change_quote_currency, self)
        self.balance_label.setObjectName("balance_label")


        # Bitcoin address code
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText(_("Enter a Groestlcoin address or contact"))
        self.address_input.setObjectName("address_input")

        self.address_input.setFocusPolicy(Qt.ClickFocus)

        self.address_input.textChanged.connect(self.address_field_changed)
        resize_line_edit_width(self.address_input,
                               "1BtaFUr3qVvAmwrsuDuu5zk6e4s2rxd2Gy")

        self.address_completions = QStringListModel()
        address_completer = QCompleter(self.address_input)
        address_completer.setCaseSensitivity(False)
        address_completer.setModel(self.address_completions)
        self.address_input.setCompleter(address_completer)

        address_layout = QHBoxLayout()
        address_layout.addWidget(self.address_input)

        self.amount_input = QLineEdit()
        self.amount_input.setPlaceholderText(_("... and amount") + " (%s)"%self.actuator.g.base_unit())
        self.amount_input.setObjectName("amount_input")

        self.amount_input.setFocusPolicy(Qt.ClickFocus)
        # This is changed according to the user's displayed balance
        self.amount_validator = QDoubleValidator(self.amount_input)
        self.amount_validator.setNotation(QDoubleValidator.StandardNotation)
        self.amount_validator.setDecimals(8)
        self.amount_input.setValidator(self.amount_validator)

        # This removes the very ugly OSX highlighting, please leave this in :D
        self.address_input.setAttribute(Qt.WA_MacShowFocusRect, 0)
        self.amount_input.setAttribute(Qt.WA_MacShowFocusRect, 0)
        self.amount_input.textChanged.connect(self.amount_input_changed)

        #if self.actuator.g.wallet.seed:
        self.send_button = QPushButton(_("&Send"))
        #else:
        #    self.send_button = QPushButton(_("&Create"))

        self.send_button.setObjectName("send_button")
        self.send_button.setDisabled(True);
        self.send_button.clicked.connect(self.send)

        # Creating the receive button
        self.switch_button = QPushButton( QIcon(":icons/switchgui.png"),'' )
        self.switch_button.setMaximumWidth(25)
        self.switch_button.setFlat(True)
        self.switch_button.clicked.connect(expand_callback)

        main_layout = QGridLayout(self)

        main_layout.addWidget(self.balance_label, 0, 0, 1, 3)
        main_layout.addWidget(self.switch_button, 0, 3)

        main_layout.addWidget(self.address_input, 1, 0, 1, 4)
        main_layout.addWidget(self.amount_input, 2, 0, 1, 2)
        main_layout.addWidget(self.send_button, 2, 2, 1, 2)

        self.send_button.setMaximumWidth(125)

        self.history_list = history_widget.HistoryWidget()
        self.history_list.setObjectName("history")
        self.history_list.hide()
        self.history_list.setAlternatingRowColors(True)

        main_layout.addWidget(self.history_list, 3, 0, 1, 4)

        self.receiving = receiving_widget.ReceivingWidget(self)
        self.receiving.setObjectName("receiving")

        # Add to the right side
        self.receiving_box = QGroupBox(_("Select a receiving address"))
        extra_layout = QGridLayout()

        # Checkbox to filter used addresses
        hide_used = QCheckBox(_('Hide used addresses'))
        hide_used.setChecked(True)
        hide_used.stateChanged.connect(self.receiving.toggle_used)

        # Events for receiving addresses
        self.receiving.clicked.connect(self.receiving.copy_address)
        self.receiving.itemDoubleClicked.connect(self.receiving.edit_label)
        self.receiving.itemChanged.connect(self.receiving.update_label)


        # Label
        extra_layout.addWidget( QLabel(_('Selecting an address will copy it to the clipboard.') + '\n' + _('Double clicking the label will allow you to edit it.') ),0,0)

        extra_layout.addWidget(self.receiving, 1,0)
        extra_layout.addWidget(hide_used, 2,0)
        extra_layout.setColumnMinimumWidth(0,200)

        self.receiving_box.setLayout(extra_layout)
        main_layout.addWidget(self.receiving_box,0,4,-1,3)
        self.receiving_box.hide()

        self.main_layout = main_layout

        quit_shortcut = QShortcut(QKeySequence("Ctrl+Q"), self)
        quit_shortcut.activated.connect(self.close)
        close_shortcut = QShortcut(QKeySequence("Ctrl+W"), self)
        close_shortcut.activated.connect(self.close)

        g = self.config.get("winpos-lite",[4, 25, 351, 149])
        self.setGeometry(g[0], g[1], g[2], g[3])

        show_hist = self.config.get("gui_show_history",False)
        self.show_history(show_hist)
        show_hist = self.config.get("gui_show_receiving",False)
        self.toggle_receiving_layout(show_hist)

        self.setWindowIcon(QIcon(":icons/electrum.png"))
        self.setWindowTitle("Electrum-GRS")
        self.setWindowFlags(Qt.Window|Qt.MSWindowsFixedSizeDialogHint)
        self.layout().setSizeConstraint(QLayout.SetFixedSize)
        self.setObjectName("main_window")


    def context_menu(self):
        view_menu = QMenu()
        themes_menu = view_menu.addMenu(_("&Themes"))
        selected_theme = self.actuator.selected_theme()
        theme_group = QActionGroup(self)
        for theme_name in self.actuator.theme_names():
            theme_action = themes_menu.addAction(theme_name)
            theme_action.setCheckable(True)
            if selected_theme == theme_name:
                theme_action.setChecked(True)
            class SelectThemeFunctor:
                def __init__(self, theme_name, toggle_theme):
                    self.theme_name = theme_name
                    self.toggle_theme = toggle_theme
                def __call__(self, checked):
                    if checked:
                        self.toggle_theme(self.theme_name)
            delegate = SelectThemeFunctor(theme_name, self.toggle_theme)
            theme_action.toggled.connect(delegate)
            theme_group.addAction(theme_action)
        view_menu.addSeparator()

        show_receiving = view_menu.addAction(_("Show Receiving addresses"))
        show_receiving.setCheckable(True)
        show_receiving.toggled.connect(self.toggle_receiving_layout)
        show_receiving.setChecked(self.config.get("gui_show_receiving",False))

        show_history = view_menu.addAction(_("Show History"))
        show_history.setCheckable(True)
        show_history.toggled.connect(self.show_history)
        show_history.setChecked(self.config.get("gui_show_history",False))

        return view_menu



    def toggle_theme(self, theme_name):
        self.actuator.change_theme(theme_name)
        # Recompute style globally
        qApp.style().unpolish(self)
        qApp.style().polish(self)

    def closeEvent(self, event):
        g = self.geometry()
        self.config.set_key("winpos-lite", [g.left(),g.top(),g.width(),g.height()],True)
        self.actuator.g.closeEvent(event)
        qApp.quit()

    def pay_from_URI(self, URI):
        try:
            dest_address, amount, label, message, request_url = util.parse_URI(URI)
        except:
            return
        self.address_input.setText(dest_address)
        self.address_field_changed(dest_address)
        self.amount_input.setText(str(amount))

    def activate(self):
        pass

    def deactivate(self):
        pass

    def set_exchange(self, use_exchange):
        if use_exchange not in self.use_exchanges:
            return
        self.use_exchanges.remove(use_exchange)
        self.use_exchanges.insert(0, use_exchange)
        self.refresh_balance()

    def set_quote_currency(self, currency):
        """Set and display the fiat currency country."""
        if currency not in self.quote_currencies:
            return
        self.quote_currencies.remove(currency)
        self.quote_currencies.insert(0, currency)
        self.refresh_balance()

    def change_quote_currency(self, forward=True):
        if forward:
            self.quote_currencies = \
                self.quote_currencies[1:] + self.quote_currencies[0:1]
        else:
            self.quote_currencies = \
                self.quote_currencies[-1:] + self.quote_currencies[0:-1]
        self.actuator.set_config_currency(self.quote_currencies[0])
        self.refresh_balance()

    def refresh_balance(self):
        if self.btc_balance is None:
            # Price has been discovered before wallet has been loaded
            # and server connect... so bail.
            return
        self.set_balances(self.btc_balance)
        self.amount_input_changed(self.amount_input.text())

    def set_balances(self, btc_balance):
        """Set the bitcoin balance and update the amount label accordingly."""
        self.btc_balance = btc_balance
        quote_text = self.create_quote_text(btc_balance)
        if quote_text:
            quote_text = "(%s)" % quote_text

        amount = self.actuator.g.format_amount(btc_balance)
        unit = self.actuator.g.base_unit()

        self.balance_label.set_balance_text(amount, unit, quote_text)
        self.setWindowTitle("Electrum-GRS %s - %s %s" % (electrum_version, amount, unit))

    def amount_input_changed(self, amount_text):
        """Update the number of bitcoins displayed."""
        self.check_button_status()

        try:
            amount = D(str(amount_text)) * (10**self.actuator.g.decimal_point)
        except decimal.InvalidOperation:
            self.balance_label.show_balance()
        else:
            quote_text = self.create_quote_text(amount)
            if quote_text:
                self.balance_label.set_amount_text(quote_text)
                self.balance_label.show_amount()
            else:
                self.balance_label.show_balance()

    def create_quote_text(self, btc_balance):
        """Return a string copy of the amount fiat currency the
        user has in bitcoins."""
        from electrum_grs.plugins import run_hook
        r = {}
        run_hook('get_fiat_balance_text', btc_balance, r)
        return r.get(0,'')

    def send(self):
        if self.actuator.send(self.address_input.text(),
                              self.amount_input.text(), self):
            self.address_input.setText("")
            self.amount_input.setText("")

    def check_button_status(self):
        """Check that the bitcoin address is valid and that something
        is entered in the amount before making the send button clickable."""
        try:
            value = D(str(self.amount_input.text())) * (10**self.actuator.g.decimal_point)
        except decimal.InvalidOperation:
            value = None
        # self.address_input.property(...) returns a qVariant, not a bool.
        # The == is needed to properly invoke a comparison.
        if (self.address_input.property("isValid") == True and
            value is not None and 0 < value <= self.btc_balance):
            self.send_button.setDisabled(False)
        else:
            self.send_button.setDisabled(True)

    def address_field_changed(self, address):
        # label or alias, with address in brackets
        match2 = re.match("(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>",
                          address)
        if match2:
          address = match2.group(2)
          self.address_input.setText(address)

        if is_valid(address):
            self.check_button_status()
            self.address_input.setProperty("isValid", True)
            self.recompute_style(self.address_input)
        else:
            self.send_button.setDisabled(True)
            self.address_input.setProperty("isValid", False)
            self.recompute_style(self.address_input)

        if len(address) == 0:
            self.address_input.setProperty("isValid", None)
            self.recompute_style(self.address_input)

    def recompute_style(self, element):
        self.style().unpolish(element)
        self.style().polish(element)

    def copy_address(self):
        receive_popup = ReceivePopup(self.receive_button)
        self.actuator.copy_address(receive_popup)

    def update_completions(self, completions):
        self.address_completions.setStringList(completions)


    def update_history(self, tx_history):

        self.history_list.empty()

        for item in tx_history[-10:]:
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            label = self.actuator.g.wallet.get_label(tx_hash)[0]
            v_str = self.actuator.g.format_amount(value, True)
            self.history_list.append(label, v_str, age(timestamp))


    def the_website(self):
        webbrowser.open("http://electrum.org")


    def toggle_receiving_layout(self, toggle_state):
        if toggle_state:
            self.receiving_box.show()
        else:
            self.receiving_box.hide()
        self.config.set_key("gui_show_receiving", toggle_state)

    def show_history(self, toggle_state):
        if toggle_state:
            self.main_layout.setRowMinimumHeight(3,200)
            self.history_list.show()
        else:
            self.main_layout.setRowMinimumHeight(3,0)
            self.history_list.hide()
        self.config.set_key("gui_show_history", toggle_state)

class BalanceLabel(QLabel):

    SHOW_CONNECTING = 1
    SHOW_BALANCE = 2
    SHOW_AMOUNT = 3

    def __init__(self, change_quote_currency, parent=None):
        super(QLabel, self).__init__(_("Connecting..."), parent)
        self.change_quote_currency = change_quote_currency
        self.state = self.SHOW_CONNECTING
        self.balance_text = ""
        self.amount_text = ""
        self.parent = parent

    def mousePressEvent(self, event):
        """Change the fiat currency selection if window background is clicked."""
        if self.state != self.SHOW_CONNECTING:
            if event.button() == Qt.LeftButton:
                self.change_quote_currency()
            else:
                position = event.globalPos()
                menu = self.parent.context_menu()
                menu.exec_(position)


    def set_balance_text(self, amount, unit, quote_text):
        """Set the amount of bitcoins in the gui."""
        if self.state == self.SHOW_CONNECTING:
            self.state = self.SHOW_BALANCE

        self.balance_text = "<span style='font-size: 18pt'>%s</span>"%amount\
            + " <span style='font-size: 10pt'>%s</span>" % unit \
            + " <span style='font-size: 10pt'>%s</span>" % quote_text

        if self.state == self.SHOW_BALANCE:
            self.setText(self.balance_text)

    def set_amount_text(self, quote_text):
        self.amount_text = "<span style='font-size: 10pt'>%s</span>" % quote_text
        if self.state == self.SHOW_AMOUNT:
            self.setText(self.amount_text)

    def show_balance(self):
        if self.state == self.SHOW_AMOUNT:
            self.state = self.SHOW_BALANCE
            self.setText(self.balance_text)

    def show_amount(self):
        if self.state == self.SHOW_BALANCE:
            self.state = self.SHOW_AMOUNT
            self.setText(self.amount_text)

def ok_cancel_buttons(dialog):
    row_layout = QHBoxLayout()
    row_layout.addStretch(1)
    ok_button = QPushButton(_("OK"))
    row_layout.addWidget(ok_button)
    ok_button.clicked.connect(dialog.accept)
    cancel_button = QPushButton(_("Cancel"))
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

class ReceivePopup(QDialog):

    def leaveEvent(self, event):
        self.close()

    def setup(self, address):
        label = QLabel(_("Copied your Groestlcoin address to the clipboard!"))
        address_display = QLineEdit(address)
        address_display.setReadOnly(True)
        resize_line_edit_width(address_display, address)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(label)
        main_layout.addWidget(address_display)

        self.setMouseTracking(True)
        self.setWindowTitle("Electrum-GRS - " + _("Receive Groestlcoin payment"))
        self.setWindowFlags(Qt.Window|Qt.FramelessWindowHint|
                            Qt.MSWindowsFixedSizeDialogHint)
        self.layout().setSizeConstraint(QLayout.SetFixedSize)
        #self.setFrameStyle(QFrame.WinPanel|QFrame.Raised)
        #self.setAlignment(Qt.AlignCenter)

    def popup(self):
        parent = self.parent()
        top_left_pos = parent.mapToGlobal(parent.rect().bottomLeft())
        self.move(top_left_pos)
        center_mouse_pos = self.mapToGlobal(self.rect().center())
        QCursor.setPos(center_mouse_pos)
        self.show()

class MiniActuator:
    """Initialize the definitions relating to themes and
    sending/receiving bitcoins."""


    def __init__(self, main_window):
        """Retrieve the gui theme used in previous session."""
        self.g = main_window
        self.theme_name = self.g.config.get('litegui_theme','Cleanlook')
        self.themes = load_theme_paths()
        self.load_theme()

    def load_theme(self):
        """Load theme retrieved from wallet file."""
        try:
            theme_prefix, theme_path = self.themes[self.theme_name]
        except KeyError:
            util.print_error("Theme not found!", self.theme_name)
            return
        full_theme_path = "%s/%s/style.css" % (theme_prefix, theme_path)
        with open(full_theme_path) as style_file:
            qApp.setStyleSheet(style_file.read())

    def theme_names(self):
        """Sort themes."""
        return sorted(self.themes.keys())

    def selected_theme(self):
        """Select theme."""
        return self.theme_name

    def change_theme(self, theme_name):
        """Change theme."""
        self.theme_name = theme_name
        self.g.config.set_key('litegui_theme',theme_name)
        self.load_theme()

    def set_configured_exchange(self, set_exchange):
        use_exchange = self.g.config.get('use_exchange')
        if use_exchange is not None:
            set_exchange(use_exchange)

    def set_configured_currency(self, set_quote_currency):
        """Set the inital fiat currency conversion country (USD/EUR/GBP) in
        the GUI to what it was set to in the wallet."""
        currency = self.g.config.get('currency')
        # currency can be none when Electrum is used for the first
        # time and no setting has been created yet.
        if currency is not None:
            set_quote_currency(currency)

    def set_config_exchange(self, conversion_exchange):
        self.g.config.set_key('exchange',conversion_exchange,True)
        self.g.update_status()

    def set_config_currency(self, conversion_currency):
        """Change the wallet fiat currency country."""
        self.g.config.set_key('currency',conversion_currency,True)
        self.g.update_status()

    def copy_address(self, receive_popup):
        """Copy the wallet addresses into the client."""
        addrs = [addr for addr in self.g.wallet.addresses(True)
                 if not self.g.wallet.is_change(addr)]
        # Select most recent addresses from gap limit
        addrs = addrs[-self.g.wallet.gap_limit:]
        copied_address = random.choice(addrs)
        qApp.clipboard().setText(copied_address)
        receive_popup.setup(copied_address)
        receive_popup.popup()

    def waiting_dialog(self, f):
        s = Timer()
        s.start()
        w = QDialog()
        w.resize(200, 70)
        w.setWindowTitle('Electrum-GRS')
        l = QLabel(_('Sending transaction, please wait.'))
        vbox = QVBoxLayout()
        vbox.addWidget(l)
        w.setLayout(vbox)
        w.show()
        def ff():
            s = f()
            if s: l.setText(s)
            else: w.close()
        w.connect(s, QtCore.SIGNAL('timersignal'), ff)
        w.exec_()
        w.destroy()


    def send(self, address, amount, parent_window):
        """Send bitcoins to the target address."""
        dest_address = self.fetch_destination(address)

        if dest_address is None or not is_valid(dest_address):
            QMessageBox.warning(parent_window, _('Error'),
                _('Invalid Groestlcoin Address') + ':\n' + address, _('OK'))
            return False

        amount = D(unicode(amount)) * (10*self.g.decimal_point)
        print "amount", amount
        return

        if self.g.wallet.use_encryption:
            password_dialog = PasswordDialog(parent_window)
            password = password_dialog.run()
            if not password:
                return
        else:
            password = None

        fee = 0
        # 0.1 BTC = 10000000
        if amount < bitcoin(1) / 10:
            # 0.001 BTC
            fee = bitcoin(1) / 1000

        try:
            tx = self.g.wallet.mktx([(dest_address, amount)], password, fee)
        except Exception as error:
            QMessageBox.warning(parent_window, _('Error'), str(error), _('OK'))
            return False

        if tx.is_complete():
            h = self.g.wallet.send_tx(tx)

            self.waiting_dialog(lambda: False if self.g.wallet.tx_event.isSet() else _("Sending transaction, please wait..."))

            status, message = self.g.wallet.receive_tx(h, tx)

            if not status:
                import tempfile
                dumpf = tempfile.NamedTemporaryFile(delete=False)
                dumpf.write(tx)
                dumpf.close()
                print "Dumped error tx to", dumpf.name
                QMessageBox.warning(parent_window, _('Error'), message, _('OK'))
                return False

            TransactionWindow(message, self)
        else:
            filename = 'unsigned_tx_%s' % (time.mktime(time.gmtime()))
            try:
                fileName = QFileDialog.getSaveFileName(QWidget(), _("Select a transaction filename"), os.path.expanduser('~/%s' % (filename)))
                with open(fileName,'w') as f:
                    f.write(json.dumps(tx.as_dict(),indent=4) + '\n')
                QMessageBox.information(QWidget(), _('Unsigned transaction created'), _("Unsigned transaction was saved to file:") + " " +fileName, _('OK'))
            except Exception as e:
                QMessageBox.warning(QWidget(), _('Error'), _('Could not write transaction to file: %s' % e), _('OK'))
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
                self.g.wallet.get_alias(recipient, True,
                                      self.show_message, self.question)
            return dest_address
        elif match2:
            return match2.group(2)
        else:
            return recipient





class MiniDriver(QObject):

    INITIALIZING = 0
    CONNECTING = 1
    SYNCHRONIZING = 2
    READY = 3

    def __init__(self, main_window, mini_window):
        super(QObject, self).__init__()

        self.g = main_window
        self.network = main_window.network
        self.window = mini_window

        if self.network:
            self.network.register_callback('updated',self.update_callback)
            self.network.register_callback('status', self.update_callback)

        self.state = None

        self.initializing()
        self.connect(self, SIGNAL("updatesignal()"), self.update)
        self.update_callback()

    # This is a hack to workaround that Qt does not like changing the
    # window properties from this other thread before the runloop has
    # been called from.
    def update_callback(self):
        self.emit(SIGNAL("updatesignal()"))

    def update(self):
        if not self.network:
            self.initializing()
        #elif not self.network.interface:
        #    self.initializing()
        elif not self.network.is_connected():
            self.connecting()

        if self.g.wallet is None:
            self.ready()
        elif not self.g.wallet.up_to_date:
            self.synchronizing()
        else:
            self.ready()
            self.update_balance()
            self.update_completions()
            self.update_history()
            self.window.receiving.update_list()


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
        conf_balance, unconf_balance = self.g.wallet.get_balance()
        balance = D(conf_balance + unconf_balance)
        self.window.set_balances(balance)

    def update_completions(self):
        completions = []
        for addr, label in self.g.wallet.labels.items():
            if addr in self.g.wallet.addressbook:
                completions.append("%s <%s>" % (label, addr))
        self.window.update_completions(completions)

    def update_history(self):
        tx_history = self.g.wallet.get_tx_history()
        self.window.update_history(tx_history)


