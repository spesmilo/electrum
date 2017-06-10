from electrum.i18n import _
import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
from electrum_gui.qt.util import *
import webbrowser
from electrum import Wallet, WalletStorage
from electrum import keystore
import requests

# TODO: if tor enable, use .onion service
base_url = "https://chipmixer.com"
api_url = base_url + "/api/v1"

class ChipMixer:
    def __init__(self, parent):
        self.parent = parent
        self.token = None
        step1 = ChipMixerStep1(self)

    def session_widget(self, layout):
        session_label = HelpLabel(_("Session Token"), _("Save this value to recover session or request help."))
        session_token = QLineEdit()
        session_token.setReadOnly(True)
        session_token.setText(self.token)
        browser_button = QPushButton(_("Show in browser"))
        browser_button.clicked.connect(lambda: webbrowser.open(self.session_link()))
        layout.addWidget(session_label, 1, 0)
        layout.addWidget(session_token, 1, 1)
        layout.addWidget(browser_button, 1, 2)

    def session_link(self):
        return base_url + "/session/restore/" + self.token

class ChipMixerStep1(WindowModalDialog):
    def __init__(self, chipmixer):
        self.chipmixer = chipmixer
        self.parent = chipmixer.parent
        WindowModalDialog.__init__(self, self.parent, _("ChipMixer: Step 1"))
        if not self.request_new_session():
            return
        self.display_window()

    def request_new_session(self):
        response = requests.request("GET", (api_url + "/new_session"), headers = {'User-Agent': 'Electrum'})
        json = response.json()
        if not json.get('success'):
            self.show_critical("ChipMixer error: " + json.get('error'))
            return False
        self.chipmixer.token = self.token = json.get('token')
        self.deposit_address = json.get('deposit_address')
        return True

    def display_window(self):
        self.setWindowModality(Qt.NonModal)
        self.setMinimumWidth(700)
        layout = QGridLayout(self)

        self.chipmixer.session_widget(layout)

        deposit_label = HelpLabel(_("Input address"), _("Send bitcoins here to mix them."))
        input_addr = QLineEdit()
        input_addr.setReadOnly(True)
        input_addr.setText(self.deposit_address)
        deposit_button = QPushButton(_("Deposit"))
        deposit_button.clicked.connect(self.do_deposit)
        layout.addWidget(deposit_label, 2, 0)
        layout.addWidget(input_addr, 2, 1)
        layout.addWidget(deposit_button, 2, 2)

        voucher_label = HelpLabel(_("Voucher code"), _("Instead of depositing bitcoins, you can spend a voucher."))
        self.voucher_edit = QLineEdit()
        redeem_button = QPushButton(_("Redeem"))
        redeem_button.clicked.connect(self.do_redeem)
        layout.addWidget(voucher_label, 3, 0)
        layout.addWidget(self.voucher_edit, 3, 1)
        layout.addWidget(redeem_button, 3, 2)

        next_button = QPushButton(_("Next step >>"))
        layout.addWidget(next_button, 4, 2)
        next_button.clicked.connect(self.step2)

        self.show()

    def do_deposit(self):
        self.parent.clear_receive_tab()
        self.parent.show_send_tab()
        self.parent.payto_e.setText(self.deposit_address)
        self.parent.message_e.setText('ChipMixer: ' + self.chipmixer.session_link())

    def do_redeem(self):
        voucher = "%s" % self.voucher_edit.text()
        if voucher == "":
            return
        response = requests.request("GET", api_url + "/" + self.chipmixer.token + "/voucher/" + voucher, headers = {'User-Agent': 'Electrum'})
        json = response.json()
        if not json.get('success'):
            self.show_critical("ChipMixer error: " + json.get('error'))
            return
        self.step2()

    def step2(self):
        if ChipMixerStep2(self.chipmixer):
            self.close()



class ChipMixerStep2(WindowModalDialog):
    def __init__(self, chipmixer):
        self.chipmixer = chipmixer
        self.parent = chipmixer.parent
        self.token = chipmixer.token
        self.chips = []
        self.logs_text = ""
        WindowModalDialog.__init__(self, self.parent, _("ChipMixer: Step 2"))
        if not self.do_request("/session"):
            return
        self.display_window()

    def do_request(self, action):
        response = requests.request("GET", (api_url + "/" + self.token + action), headers = {'User-Agent': 'Electrum'})
        json = response.json()
        if not json.get('success'):
            self.show_critical("ChipMixer error: " + json.get('error'))
            return False
        self.chips = json.get('chips')
        self.logs_text = json.get('logs_text')
        return True

    def display_window(self):
        self.setWindowModality(Qt.NonModal)
        self.setMinimumWidth(600)
        layout = QGridLayout(self)

        self.chipmixer.session_widget(layout)

        chips_label = QLabel(_("Chips"))
        layout.addWidget(chips_label, 2, 0)

        self.chip_layout = QVBoxLayout()
        self.redraw_chip_layout()
        layout.addLayout(self.chip_layout, 2, 1)
        refresh_button = QPushButton(_("Refresh"))
        layout.addWidget(refresh_button, 2, 2)
        refresh_button.clicked.connect(lambda: self.request_and_refresh("/session"))

        logs_label = QLabel(_("Logs"))
        layout.addWidget(logs_label, 3, 0)
        self.logs_edit = QTextEdit()
        self.logs_edit.setMinimumHeight(200)
        self.redraw_logs()
        layout.addWidget(self.logs_edit, 3, 1)

        next_button = QPushButton(_("Withdraw all >>"))
        layout.addWidget(next_button, 3, 2)
        next_button.clicked.connect(self.step3)
        self.show()

    def redraw_chip_layout(self):
        layout = self.chip_layout
        for i in reversed(range(layout.count())):
            row = layout.itemAt(i).layout()
            for j in reversed(range(row.count())):
                widget = row.itemAt(j).widget()
                row.removeWidget(widget)
                widget.deleteLater()
            row.setParent(None)
        for [size, count] in self.chips:
            size_s = str(size)
            count_s = str(count)
            row = QHBoxLayout()
            # TODO: check Electrum config if mBTC is prefered
            row.addWidget(QLabel(count_s + " x " + size_s + " mBTC"))
            split_button = QPushButton(_("Split"))
            if size == 1:
                split_button.setEnabled(False)
            split_button.clicked.connect(partial(self.request_and_refresh, "/split/" + size_s))
            row.addWidget(split_button)
            merge_button = QPushButton(_("Merge"))
            if count < 2:
                merge_button.setEnabled(False)
            merge_button.clicked.connect(partial(self.request_and_refresh, "/merge/" + size_s))
            row.addWidget(merge_button)
            bet_button = QPushButton(_("Bet"))
            bet_button.clicked.connect(partial(self.request_and_refresh, "/bet/" + size_s))
            row.addWidget(bet_button)
            donate_button = QPushButton(_("Donate"))
            donate_button.clicked.connect(partial(self.request_and_refresh, "/donate/" + size_s))
            row.addWidget(donate_button)
            layout.addLayout(row)
        if len(self.chips) == 0:
            row = QHBoxLayout()
            row.addWidget(QLabel(_("You have no chips.")))
            layout.addLayout(row)
        return layout

    def redraw_logs(self):
        self.logs_edit.setText(self.logs_text)

    def request_and_refresh(self, action):
        if not self.do_request(action):
            return
        self.redraw_chip_layout()
        self.redraw_logs()

    def request_withdraw(self):
        response = requests.request("GET", api_url + "/" + self.token + "/withdraw_all", headers = {'User-Agent': 'Electrum'})
        json = response.json()
        if not json.get('success'):
            self.show_critical("ChipMixer error: " + json.get('error'))
            return False
        return json.get('privkeys_text')

    def step3(self):
        privkeys = self.request_withdraw()
        if not privkeys:
            return
        self.request_and_refresh("/session")
        self.logs_edit.setText("Your private keys:\n" + privkeys)
        full_path = self.new_wallet_path()
        if not full_path:
            return
        self.create_wallet_with_privkeys(full_path, privkeys)
        self.parent.gui_object.start_new_window(full_path, None)

    def new_wallet_path(self):
        wallet_folder = self.parent.get_wallet_folder()
        i = 1
        while True:
            filename = "chipmixer_%d" % i
            if filename in os.listdir(wallet_folder):
                i += 1
            else:
                break
        filename = line_dialog(self, _('New Wallet'), _('Enter file name')
            + ':', _('OK'), filename)
        if not filename:
            return
        full_path = os.path.join(wallet_folder, filename)
        if os.path.exists(full_path):
            self.show_critical(_("File exists"))
            return
        return full_path

    def create_wallet_with_privkeys(self, full_path, privkeys):
        k = keystore.from_keys(privkeys)
        storage = WalletStorage(full_path)
        storage.put('seed', None)
        storage.put('seed_version', None)
        storage.put('master_public_key', None)
        storage.put('wallet_type', 'standard')
        storage.put('keystore', k.dump())
        storage.write()


    def session_link(self):
        return base_url + "/session/restore/" + self.token
