from PyQt4.QtCore import *
from PyQt4.QtGui import *
import sys

_ = lambda trtext: trtext

def IconButton(filename, parent=None):
    pixmap = QPixmap(filename)
    icon = QIcon(pixmap)
    return QPushButton(icon, "", parent)

class ElectrumGui:
    def __init__(self, wallet):
        self.wallet = wallet

    def main(self, url):
        print url
        # Do nothing.

class MiniWindow(QDialog):
    def __init__(self):
        super(MiniWindow, self).__init__()

        accounts_button = IconButton("data/icons/accounts.png")
        accounts_button.setObjectName("accounts_button")

        accounts_selector = QMenu()
        accounts_selector.addAction("Normal (80.00 BTC)")
        accounts_selector.addAction("Drugs (7.50 BTC)")
        accounts_selector.addAction("Reddit Girls (3.50 BTC)")
        accounts_button.setMenu(accounts_selector)

        interact_button = IconButton("data/icons/interact.png")
        interact_button.setObjectName("interact_button")

        app_menu = QMenu()
        app_menu.addAction("Blaa")
        file_menu = QMenu("File", app_menu)
        file_menu.addAction("Foo")
        file_menu.addAction("Bar")
        app_menu.addMenu(file_menu)
        app_menu.addAction("Other")
        interact_button.setMenu(app_menu)

        expand_button = IconButton("data/icons/expand.png")
        expand_button.setObjectName("expand_button")

        balance_label = BalanceLabel("80.00", "60.00", "EUR")
        balance_label.setObjectName("balance_label")

        copy_button = QPushButton(_("&Copy Address"))
        copy_button.setObjectName("copy_button")
        copy_button.setDefault(True)

        # Use QCompleter
        address_input = TextedLineEdit(_("Enter a Bitcoin address..."))
        address_input.setObjectName("address_input")
        valid_address = QCheckBox()
        valid_address.setObjectName("valid_address")
        valid_address.setEnabled(False)
        #valid_address.setChecked(True)

        address_layout = QHBoxLayout()
        address_layout.addWidget(address_input)
        address_layout.addWidget(valid_address)

        amount_input = TextedLineEdit(_("... and amount"))
        amount_input.setObjectName("amount_input")

        amount_layout = QHBoxLayout()
        amount_layout.addWidget(amount_input)
        amount_layout.addStretch()

        send_button = QPushButton(_("&Send"))
        send_button.setObjectName("send_button")

        main_layout = QGridLayout(self)
        main_layout.addWidget(accounts_button, 0, 0)
        main_layout.addWidget(interact_button, 1, 0)
        main_layout.addWidget(expand_button, 2, 0)

        main_layout.addWidget(balance_label, 0, 1)
        main_layout.addWidget(copy_button, 0, 2)

        main_layout.addLayout(address_layout, 1, 1, 1, -1)

        main_layout.addLayout(amount_layout, 2, 1)
        main_layout.addWidget(send_button, 2, 2)

        self.setWindowTitle("Electrum - Normal (80.00 BTC)")
        self.setWindowFlags(Qt.Window|Qt.MSWindowsFixedSizeDialogHint)
        self.layout().setSizeConstraint(QLayout.SetFixedSize)
        self.setObjectName("main_window")
        self.show()

    def closeEvent(self, event):
        super(MiniWindow, self).closeEvent(event)
        qApp.quit()

class BalanceLabel(QLabel):
    def __init__(self, btc_balance,
                 quote_balance, quote_currency, parent=None):
        label_text = "<span style='font-size: 16pt'>%s</span> <span style='font-size: 10pt'>BTC</span> <span style='font-size: 10pt'>(%s %s)</span>"%(btc_balance, quote_balance, quote_currency)
        super(QLabel, self).__init__(label_text, parent)

class TextedLineEdit(QLineEdit):
    def __init__(self, inactive_text, parent=None):
        super(QLineEdit, self).__init__(parent)
        self.inactive_text = inactive_text
        self.become_inactive()

    def mousePressEvent(self, event):
        if self.isReadOnly():
            self.become_active()
        return super(QLineEdit, self).mousePressEvent(event)

    def focusOutEvent(self, event):
        if self.text() == "":
            self.become_inactive()
        return super(QLineEdit, self).focusOutEvent(event)

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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    with open("data/style.css") as style_file:
        app.setStyleSheet(style_file.read())
    mini = MiniWindow()
    sys.exit(app.exec_())

