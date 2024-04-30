import tty
import sys
import curses
import datetime
import locale
from decimal import Decimal
import getpass
from typing import TYPE_CHECKING, Optional

# 3rd-party dependency:
try:
    import pyperclip
except ImportError:  # only use vendored lib as fallback, to allow Linux distros to bring their own
    from electrum._vendor import pyperclip

import electrum
from electrum.gui import BaseElectrumGui
from electrum.bip21 import parse_bip21_URI
from electrum.util import format_satoshis, format_time
from electrum.util import EventListener, event_listener
from electrum.bitcoin import is_address, address_to_script, COIN
from electrum.transaction import PartialTxOutput
from electrum.wallet import Wallet, Abstract_Wallet
from electrum.wallet_db import WalletDB
from electrum.storage import WalletStorage
from electrum.network import NetworkParameters, TxBroadcastError, BestEffortRequestFailed
from electrum.interface import ServerAddr
from electrum.invoices import Invoice

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins


_ = lambda x:x  # i18n


# ascii key codes
KEY_BACKSPACE = 8
KEY_ESC = 27
KEY_DELETE = 127


def parse_bip21(text):
    try:
        return parse_bip21_URI(text)
    except Exception:
        return


def parse_bolt11(text):
    from electrum.lnaddr import lndecode
    try:
        return lndecode(text)
    except Exception:
        return


class ElectrumGui(BaseElectrumGui, EventListener):

    def __init__(self, *, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        BaseElectrumGui.__init__(self, config=config, daemon=daemon, plugins=plugins)
        self.network = daemon.network
        storage = WalletStorage(config.get_wallet_path(use_gui_last_wallet=True))
        if not storage.file_exists():
            print("Wallet not found. try 'electrum create'")
            exit()
        if storage.is_encrypted():
            password = getpass.getpass('Password:', stream=None)
            storage.decrypt(password)
        db = WalletDB(storage.read(), storage=storage, upgrade=True)
        self.wallet = Wallet(db, config=config)  # type: Optional[Abstract_Wallet]
        self.wallet.start_network(self.network)
        self.contacts = self.wallet.contacts

        locale.setlocale(locale.LC_ALL, '')
        self.encoding = locale.getpreferredencoding()

        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_CYAN)
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.halfdelay(1)
        self.stdscr.keypad(1)
        self.stdscr.border(0)
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        self.set_cursor(0)
        self.w = curses.newwin(10, 50, 5, 5)

        self.lightning_invoice = None
        self.tab = 0
        self.pos = 0
        self.popup_pos = 0

        self.str_recipient = ""
        self.str_description = ""
        self.str_amount = ""
        self.history = None
        self.txid = []
        self.str_recv_description = ""
        self.str_recv_amount = ""
        self.str_recv_expiry = ""
        self.channel_ids = []
        self.requests = []

        self.register_callbacks()
        self.tab_names = [_("History"), _("Send"), _("Receive"), _("Addresses"), _("Coins"), _("Channels"), _("Contacts"), _("Banner")]
        self.num_tabs = len(self.tab_names)
        self.need_update = False

    def stop(self):
        self.tab = -1

    @event_listener
    def on_event_wallet_updated(self, wallet):
        self.need_update = True

    @event_listener
    def on_event_network_updated(self):
        self.need_update = True

    def set_cursor(self, x):
        try:
            curses.curs_set(x)
        except Exception:
            pass

    def restore_or_create(self):
        pass

    def verify_seed(self):
        pass

    def get_string(self, y, x):
        self.set_cursor(1)
        curses.echo()
        self.stdscr.addstr(y, x, " "*20, curses.A_REVERSE)
        s = self.stdscr.getstr(y,x)
        curses.noecho()
        self.set_cursor(0)
        return s

    def update(self):
        self.update_history()
        if self.tab == 0:
            self.print_history()
        self.refresh()
        self.need_update = False

    def print_button(self, x, y, text, pos):
        self.stdscr.addstr(x, y, text, curses.A_REVERSE if self.pos%self.max_pos==pos else curses.color_pair(2))

    def print_edit_line(self, y, x, label, text, index, size):
        text += " "*(size - len(text))
        self.stdscr.addstr(y, x, label)
        self.stdscr.addstr(y, x + 13, text, curses.A_REVERSE if self.pos%self.max_pos==index else curses.color_pair(1))

    def print_history(self):
        x = 2
        self.history_format_str = self.format_column_width(x, [-20, '*', 15, 15])
        if self.history is None:
            self.update_history()
        self.print_list(2, x, self.history[::-1], headers=self.history_format_str%(_("Date"), _("Description"), _("Amount"), _("Balance")))

    def update_history(self):
        width = [20, 40, 14, 14]
        delta = (self.maxx - sum(width) - 4)/3
        domain = self.wallet.get_addresses()
        self.history = []
        self.txid = []
        balance_sat = 0
        for item in self.wallet.get_full_history().values():
            amount_sat = item['value'].value
            balance_sat += amount_sat
            if item.get('lightning'):
                timestamp = item['timestamp']
                label = self.wallet.get_label_for_rhash(item['payment_hash'])
                self.txid.insert(0, item['payment_hash'])
            else:
                conf = item['confirmations']
                timestamp = item['timestamp'] if conf > 0 else 0
                label = self.wallet.get_label_for_txid(item['txid'])
                self.txid.insert(0, item['txid'])
            if timestamp:
                time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            else:
                time_str = 'unconfirmed'

            if len(label) > 40:
                label = label[0:37] + '...'
            self.history.append(self.history_format_str % (
                time_str, label,
                self.config.format_amount(amount_sat, whitespaces=True),
                self.config.format_amount(balance_sat, whitespaces=True)))

    def print_clipboard(self):
        return
        c = pyperclip.paste()
        if c:
            if len(c) > 20:
                c = c[0:20] + '...'
            self.stdscr.addstr(self.maxy -1, self.maxx // 3, ' ' + _('Clipboard') + ': ' + c + ' ')

    def print_balance(self):
        if not self.network:
            msg = _("Offline")
        elif self.network.is_connected():
            if not self.wallet.is_up_to_date():
                msg = _("Synchronizing...")
            else:
                balance = sum(self.wallet.get_balances_for_piechart())
                msg = _("Balance") + ': ' + self.config.format_amount_and_units(balance)
        else:
            msg = _("Not connected")
        msg = ' ' + msg + ' '
        self.stdscr.addstr(self.maxy -1, 3, msg)
        for i in range(self.num_tabs):
            self.stdscr.addstr(0, 2 + 2*i + len(''.join(self.tab_names[0:i])), ' '+self.tab_names[i]+' ', curses.A_REVERSE if self.tab == i else 0)
        self.stdscr.addstr(self.maxy -1, self.maxx-30, ' ' + ' '.join([_("Settings"), _("Network"), _("Quit")]) + ' ')

    def print_receive_tab(self):
        self.stdscr.clear()
        self.buttons = {}
        self.max_pos = 5 + len(list(self.wallet.get_unpaid_requests()))
        self.index = 0
        self.add_edit_line(3, 2, _("Description"), self.str_recv_description, 40)
        self.add_edit_line(5, 2, _("Amount"), self.str_recv_amount, 15)
        self.stdscr.addstr(5, 31, self.config.get_base_unit())
        self.add_edit_line(7, 2, _("Expiry"), self.str_recv_expiry, 15)
        self.add_button(9, 15, _("[Create]"), self.do_create_request)
        self.add_button(9, 25, _("[Clear]"), self.do_clear_request)
        self.print_requests_list(13, 2, offset_pos=5)
        return

    def run_receive_tab(self, c):
        if self.pos == 0:
            self.str_recv_description = self.edit_str(self.str_recv_description, c)
        elif self.pos == 1:
            self.str_recv_amount = self.edit_str(self.str_recv_amount, c)
        elif self.pos in self.buttons and c == ord("\n"):
            self.buttons[self.pos]()
        elif self.pos >= 5 and c == ord("\n"):
            key = self.requests[self.pos - 5]
            self.show_request(key)

    def question(self, msg):
        out = self.run_popup(msg, ["No", "Yes"]).get('button')
        return out == "Yes"

    def show_invoice_menu(self):
        key = self.invoices[self.pos - 7]
        invoice = self.wallet.get_invoice(key)
        out = self.run_popup('Invoice', ["Pay", "Delete"]).get('button')
        if out == "Pay":
            self.do_pay_invoice(invoice)
        elif out == "Delete":
            self.wallet.delete_invoice(key)
            self.max_pos -= 1

    def format_column_width(self, offset, width):
        delta = self.maxx -2 -offset - sum([abs(x) for x in width if x != '*'])
        fmt = ''
        for w in width:
            if w == '*':
                fmt += "%-" + "%d"%delta + "s"
            else:
                fmt += "%" + "%d"%w + "s"
        return fmt

    def print_invoices_list(self, y, x, offset_pos):
        messages = []
        invoices = []
        fmt = self.format_column_width(x, [-20, '*', 15, 25])
        headers = fmt % ("Date", "Description", "Amount", "Status")
        for req in self.wallet.get_unpaid_invoices():
            key = req.get_id()
            status = self.wallet.get_invoice_status(req)
            status_str = req.get_status_str(status)
            timestamp = req.get_time()
            date = format_time(timestamp)
            amount = req.get_amount_sat()
            message = req.get_message()
            amount_str = self.config.format_amount(amount) if amount else ""
            labels = []
            messages.append(fmt % (date, message, amount_str, status_str))
            invoices.append(key)
        self.invoices = invoices
        self.print_list(y, x, messages, headers=headers, offset_pos=offset_pos)

    def print_requests_list(self, y, x, offset_pos):
        messages = []
        requests = []
        fmt = self.format_column_width(x, [-20, '*', 15, 25])
        headers = fmt % ("Date", "Description", "Amount", "Status")
        for req in self.wallet.get_unpaid_requests():
            key = req.get_id()
            status = self.wallet.get_invoice_status(req)
            status_str = req.get_status_str(status)
            timestamp = req.get_time()
            date = format_time(timestamp)
            amount = req.get_amount_sat()
            message = req.get_message()
            amount_str = self.config.format_amount(amount) if amount else ""
            labels = []
            messages.append(fmt % (date, message, amount_str, status_str))
            requests.append(key)
        self.requests = requests
        self.print_list(y, x, messages, headers=headers, offset_pos=offset_pos)

    def print_contacts(self):
        messages = list(map(lambda x: "%20s   %45s "%(x[0], x[1][1]), self.contacts.items()))
        self.print_list(2, 1, messages, "%19s  %15s "%("Key", "Value"))

    def print_addresses(self):
        x = 2
        fmt = self.format_column_width(x, [-50, '*', 15])
        messages = [ fmt % (
            addr,
            self.wallet.get_label_for_address(addr),
            self.config.format_amount(sum(self.wallet.get_addr_balance(addr)), whitespaces=True)
        ) for addr in self.wallet.get_addresses() ]
        self.print_list(2, x, messages, fmt % ("Address", "Description", "Balance"))

    def print_utxos(self):
        x = 2
        fmt = self.format_column_width(x, [-70, '*', 15])
        utxos = self.wallet.get_utxos()
        messages = [ fmt % (
            utxo.prevout.to_str(),
            self.wallet.get_label_for_txid(utxo.prevout.txid.hex()),
            self.config.format_amount(utxo.value_sats(), whitespaces=True)
        ) for utxo in utxos]
        self.print_list(2, x, sorted(messages), fmt % ("Outpoint", "Description", "Balance"))

    def print_channels(self):
        if not self.wallet.lnworker:
            return
        fmt = "%-35s  %-10s  %-30s"
        channels = self.wallet.lnworker.get_channel_objects()
        messages = []
        channel_ids = []
        for chan in channels.values():
            channel_ids.append(chan.short_id_for_GUI())
            messages.append(fmt % (chan.short_id_for_GUI(), self.config.format_amount(chan.get_capacity()), chan.get_state().name))
        self.channel_ids = channel_ids
        self.print_list(2, 1, messages, fmt % ("Scid", "Capacity", "State"))

    def print_send_tab(self):
        self.stdscr.clear()
        self.buttons = {}
        self.max_pos = 7 + len(list(self.wallet.get_unpaid_invoices()))
        self.index = 0
        self.add_edit_line(3, 2, _("Pay to"), self.str_recipient, 40)
        self.add_edit_line(5, 2, _("Description"), self.str_description, 40)
        self.add_edit_line(7, 2, _("Amount"), self.str_amount, 15)
        self.stdscr.addstr(7, 31, self.config.get_base_unit())
        self.add_button(9, 15, _("[Paste]"), self.do_paste)
        self.add_button(9, 25, _("[Clear]"), self.do_clear)
        self.add_button(9, 35, _("[Save]"), self.do_save_invoice)
        self.add_button(9, 44, _("[Pay]"), self.do_pay)
        #
        self.print_invoices_list(13, 2, offset_pos=7)

    def add_edit_line(self, y, x, title, data, length):
        self.print_edit_line(y, x, title, data, self.index, length)
        self.index += 1

    def add_button(self, y, x, title, action):
        self.print_button(y, x, title, self.index)
        self.buttons[self.index] = action
        self.index += 1

    def print_banner(self):
        if self.network and self.network.banner:
            banner = self.network.banner
            banner = banner.replace('\r', '')
            self.print_list(2, 1, banner.split('\n'))

    def get_qr(self, data):
        import qrcode
        try:
            from StringIO import StringIO
        except ImportError:
            from io import StringIO
        s = StringIO()
        self.qr = qrcode.QRCode()
        self.qr.add_data(data)
        self.qr.print_ascii(out=s, invert=False)
        msg = s.getvalue()
        lines = msg.split('\n')
        return lines

    def print_qr(self, w, y, x, lines):
        try:
            for i, l in enumerate(lines):
                l = l.encode("utf-8")
                w.addstr(y + i, x, l, curses.color_pair(3))
        except curses.error:
            m = 'error. screen too small?'
            m = m.encode(self.encoding)
            w.addstr(y, x, m, 0)

    def print_list(self, y, x, lst, headers=None, offset_pos=0):
        self.list_length = len(lst)
        if not self.list_length:
            return
        if headers:
            headers += " "*(self.maxx -2 - len(headers))
            self.stdscr.addstr(y, x, headers, curses.A_BOLD)
        for i in range(self.maxy - 2 - y):
            msg = lst[i] if i < self.list_length else ""
            msg += " "*(self.maxx - 2 - len(msg))
            m = msg[0:self.maxx - 2]
            m = m.encode(self.encoding)
            selected = self.pos >= offset_pos and (i == ((self.pos - offset_pos) % self.list_length))
            self.stdscr.addstr(i+y+1, x, m, curses.A_REVERSE if selected else 0)

        self.max_pos = self.list_length + offset_pos

    def refresh(self):
        if self.tab == -1:
            return
        self.stdscr.border(0)
        self.print_balance()
        self.print_clipboard()
        self.stdscr.refresh()

    def increase_cursor(self, delta):
        self.pos += delta
        self.pos = max(0, self.pos)
        self.pos = min(self.pos, self.max_pos - 1)

    def getch(self, redraw=False):
        while True:
            c = self.stdscr.getch()
            if c != -1:
                return c
            if self.need_update and redraw:
                self.update()
            if self.tab == -1:
                return KEY_ESC

    def main_command(self):
        c = self.getch(redraw=True)
        cc = curses.unctrl(c).decode()
        if   c == curses.KEY_RIGHT:
            self.tab = (self.tab + 1)%self.num_tabs
        elif c == curses.KEY_LEFT:
            self.tab = (self.tab - 1)%self.num_tabs
        elif c in [curses.KEY_DOWN, ord("\t")]:
            self.increase_cursor(1)
        elif c == curses.KEY_UP:
            self.increase_cursor(-1)
        elif cc in ['^W', '^C', '^X', '^Q']:
            self.tab = -1
        elif cc in ['^N']:
            self.network_dialog()
        elif cc == '^S':
            self.settings_dialog()
        else:
            return c

    def run_tab(self, i, print_func, exec_func):
        while self.tab == i:
            self.stdscr.clear()
            print_func()
            self.refresh()
            c = self.main_command()
            if c: exec_func(c)

    def run_history_tab(self, c):
        # Get txid from cursor position
        if c == ord("\n"):
            out = self.run_popup('', ['Transaction ID:', self.txid[self.pos]])

    def edit_str(self, target, c, is_num=False):
        if target is None:
            target = ''
        # detect backspace
        cc = curses.unctrl(c).decode()
        if c in [KEY_BACKSPACE, KEY_DELETE, curses.KEY_BACKSPACE] and target:
            target = target[:-1]
        elif not is_num or cc in '0123456789.':
            target += cc
        return target

    def run_send_tab(self, c):
        self.pos = self.pos % self.max_pos
        if self.pos == 0:
            self.str_recipient = self.edit_str(self.str_recipient, c)
        elif self.pos == 1:
            self.str_description = self.edit_str(self.str_description, c)
        elif self.pos == 2:
            self.str_amount = self.edit_str(self.str_amount, c, True)
        elif self.pos in self.buttons and c == ord("\n"):
            self.buttons[self.pos]()
        elif self.pos >= 7 and c == ord("\n"):
            self.show_invoice_menu()

    def run_contacts_tab(self, c):
        if c == ord("\n") and self.contacts:
            out = self.run_popup('Address', ["Copy", "Pay to", "Edit label", "Delete"]).get('button')
            key = list(self.contacts.keys())[self.pos%len(self.contacts.keys())]
            if out == "Pay to":
                self.tab = 1
                self.str_recipient = key
                self.pos = 2
            elif out == "Edit label":
                s = self.get_string(6 + self.pos, 18)
                if s:
                    self.wallet.set_label(key, s)

    def run_addresses_tab(self, c):
        pass

    def run_utxos_tab(self, c):
        pass

    def run_channels_tab(self, c):
        if c == ord("\n"):
            out = self.run_popup('Channel Details', ['Short channel ID:', self.channel_ids[self.pos]])

    def run_banner_tab(self, c):
        self.show_message(repr(c))
        pass

    def main(self):
        self.daemon.start_network()
        tty.setraw(sys.stdin)
        try:
            while self.tab != -1:
                self.run_tab(0, self.print_history,       self.run_history_tab)
                self.run_tab(1, self.print_send_tab,      self.run_send_tab)
                self.run_tab(2, self.print_receive_tab,   self.run_receive_tab)
                self.run_tab(3, self.print_addresses,     self.run_addresses_tab)
                self.run_tab(4, self.print_utxos,         self.run_utxos_tab)
                self.run_tab(5, self.print_channels,      self.run_channels_tab)
                self.run_tab(6, self.print_contacts,      self.run_contacts_tab)
                self.run_tab(7, self.print_banner,        self.run_banner_tab)
        except curses.error as e:
            raise Exception("Error with curses. Is your screen too small?") from e
        finally:
            tty.setcbreak(sys.stdin)
            curses.nocbreak()
            self.stdscr.keypad(0)
            curses.echo()
            curses.endwin()

    def do_clear(self):
        self.str_amount = ''
        self.str_recipient = ''
        self.str_fee = ''
        self.str_description = ''

    def do_create_request(self):
        amount_sat = self.parse_amount(self.str_recv_amount)
        if not amount_sat:
            self.show_message(_('Invalid Amount'))
            return
        if amount_sat < self.wallet.dust_threshold():
            address = None
            if not self.wallet.has_lightning():
                return
        else:
            address = self.wallet.get_unused_address()
            if not address:
                return
        message = self.str_recv_description
        expiry = self.config.WALLET_PAYREQ_EXPIRY_SECONDS
        key = self.wallet.create_request(amount_sat, message, expiry, address)
        self.do_clear_request()
        self.pos = self.max_pos
        self.show_request(key)

    def do_clear_request(self):
        self.str_recv_amount = ""
        self.str_recv_description = ""

    def do_paste(self):
        text = pyperclip.paste()
        text = text.strip()
        if not text:
            return
        if is_address(text):
            self.str_recipient = text
            self.lightning_invoice = None
        elif out := parse_bip21(text):
            amount_sat = out.get('amount')
            self.str_amount = self.config.format_amount(amount_sat) if amount_sat is not None else ''
            self.str_recipient = out.get('address') or ''
            self.str_description = out.get('message') or ''
            self.lightning_invoice = None
        elif lnaddr := parse_bolt11(text):
            amount_sat = lnaddr.get_amount_sat()
            self.str_recipient = lnaddr.pubkey.serialize().hex()
            self.str_description = lnaddr.get_description()
            self.str_amount = self.config.format_amount(amount_sat) if amount_sat is not None else ''
            self.lightning_invoice = text
        else:
            self.show_message(_('Could not parse clipboard text') + '\n\n' + text[0:20] + '...')

    def parse_amount(self, text):
        try:
            x = Decimal(text)
        except Exception:
            return None
        power = pow(10, self.config.get_decimal_point())
        return int(power * x)

    def read_invoice(self):
        if self.lightning_invoice:
            invoice = Invoice.from_bech32(self.lightning_invoice)
            if invoice.amount_msat is None:
                amount_sat = self.parse_amount(self.str_amount)
                if amount_sat:
                    invoice.set_amount_msat(int(amount_sat * 1000))
                else:
                    self.show_error(_('No amount'))
                    return
        elif is_address(self.str_recipient):
            amount_sat = self.parse_amount(self.str_amount)
            scriptpubkey = address_to_script(self.str_recipient)
            outputs = [PartialTxOutput(scriptpubkey=scriptpubkey, value=amount_sat)]
            invoice = self.wallet.create_invoice(
                outputs=outputs,
                message=self.str_description,
                pr=None,
                URI=None)
        else:
            self.show_message(_('Invalid Bitcoin address'))
            return
        return invoice

    def do_save_invoice(self):
        invoice = self.read_invoice()
        if not invoice:
            return
        self.save_pending_invoice(invoice)

    def save_pending_invoice(self, invoice):
        self.do_clear()
        self.wallet.save_invoice(invoice)
        self.pending_invoice = None

    def do_pay(self):
        invoice = self.read_invoice()
        if not invoice:
            return
        self.do_pay_invoice(invoice)

    def do_pay_invoice(self, invoice):
        if invoice.is_lightning():
            self.pay_lightning_invoice(invoice)
        else:
            self.pay_onchain_dialog(invoice)

    def pay_lightning_invoice(self, invoice):
        amount_msat = invoice.get_amount_msat()
        msg = _("Pay lightning invoice?")
        #+ '\n\n' + _("This will send {}?").format(self.format_amount_and_units(Decimal(amount_msat)/1000))
        if not self.question(msg):
            return
        self.save_pending_invoice(invoice)
        coro = self.wallet.lnworker.pay_invoice(invoice.lightning_invoice, amount_msat=amount_msat)

        #self.window.run_coroutine_from_thread(coro, _('Sending payment'))
        self.show_message(_("Please wait..."), getchar=False)
        try:
            self.network.run_from_another_thread(coro)
        except Exception as e:
            self.show_message(str(e))
        else:
            self.show_message(_('Payment sent.'))

    def pay_onchain_dialog(self, invoice):
        if self.wallet.has_password():
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None
        try:
            tx = self.wallet.create_transaction(
                outputs=invoice.outputs,
                password=password,
                fee=None,
            )
        except Exception as e:
            self.show_message(repr(e))
            return
        if self.str_description:
            self.wallet.set_label(tx.txid(), self.str_description)

        self.save_pending_invoice(invoice)
        self.show_message(_("Please wait..."), getchar=False)
        try:
            self.network.run_from_another_thread(self.network.broadcast_transaction(tx))
        except TxBroadcastError as e:
            msg = e.get_message_for_gui()
            self.show_message(msg)
        except BestEffortRequestFailed as e:
            msg = repr(e)
            self.show_message(msg)
        else:
            self.show_message(_('Payment sent.'))
            self.do_clear()
            #self.update_contacts_tab()

    def show_message(self, message, getchar = True):
        w = self.w
        w.clear()
        w.border(0)
        for i, line in enumerate(message.split('\n')):
            w.addstr(2+i,2,line)
        w.refresh()
        if getchar:
            c = self.getch()

    def run_popup(self, title, items):
        return self.run_dialog(title, list(map(lambda x: {'type':'button','label':x}, items)), interval=1, y_pos = self.pos+3)

    def network_dialog(self):
        if not self.network:
            return
        net_params = self.network.get_parameters()
        server_addr = net_params.server
        proxy_config, auto_connect = net_params.proxy, net_params.auto_connect
        srv = 'auto-connect' if auto_connect else str(self.network.default_server)
        out = self.run_dialog('Network', [
            {'label': 'server', 'type': 'str', 'value': srv},
            {'label': 'proxy', 'type': 'str', 'value': self.config.NETWORK_PROXY},
            {'label': 'proxy user', 'type': 'str', 'value': self.config.NETWORK_PROXY_USER},
            {'label': 'proxy pass', 'type': 'str', 'value': self.config.NETWORK_PROXY_PASSWORD},
            ], buttons=1)
        if out:
            self.show_message(repr(proxy_config))
            if out.get('server'):
                server_str = out.get('server')
                auto_connect = server_str == 'auto-connect'
                if not auto_connect:
                    try:
                        server_addr = ServerAddr.from_str(server_str)
                    except Exception:
                        self.show_message("Error:" + server_str + "\nIn doubt, type \"auto-connect\"")
                        return False
            if out.get('server') or out.get('proxy') or out.get('proxy user') or out.get('proxy pass'):
                new_proxy_config = electrum.network.deserialize_proxy(out.get('proxy')) if out.get('proxy') else proxy_config
                if new_proxy_config:
                    new_proxy_config['user'] = out.get('proxy user') if 'proxy user' in out else proxy_config['user']
                    new_proxy_config['pass'] = out.get('proxy pass') if 'proxy pass' in out else proxy_config['pass']
                net_params = NetworkParameters(
                    server=server_addr,
                    proxy=new_proxy_config,
                    auto_connect=auto_connect)
                self.network.run_from_another_thread(self.network.set_parameters(net_params))

    def settings_dialog(self):
        fee = str(Decimal(self.config.fee_per_kb()) / COIN)
        out = self.run_dialog('Settings', [
            {'label':'Default fee', 'type':'satoshis', 'value': fee}
            ], buttons = 1)
        if out:
            if out.get('Default fee'):
                fee = int(Decimal(out['Default fee']) * COIN)
                self.config.FEE_EST_STATIC_FEERATE = fee

    def password_dialog(self):
        out = self.run_dialog('Password', [
            {'label':'Password', 'type':'password', 'value':''}
            ], buttons = 1)
        return out.get('Password')

    def run_dialog(self, title, items, interval=2, buttons=None, y_pos=3):
        self.popup_pos = 0

        self.w = curses.newwin(5 + len(list(items))*interval + (2 if buttons else 0), 68, y_pos, 5)
        w = self.w
        out = {}
        while True:
            w.clear()
            w.border(0)
            w.addstr(0, 2, title)
            num = len(list(items))
            numpos = num
            if buttons:
                numpos += 2
            for i in range(num):
                item = items[i]
                label = item.get('label')
                if item.get('type') == 'list':
                    value = item.get('value','')
                elif item.get('type') == 'satoshis':
                    value = item.get('value','')
                elif item.get('type') == 'str':
                    value = item.get('value','')
                elif item.get('type') == 'password':
                    value = '*'*len(item.get('value',''))
                else:
                    value = ''
                if value is None:
                    value = ''
                if len(value)<20:
                    value += ' '*(20-len(value))

                if 'value' in item:
                    w.addstr(2+interval*i, 2, label)
                    w.addstr(2+interval*i, 15, value, curses.A_REVERSE if self.popup_pos%numpos==i else curses.color_pair(1))
                else:
                    w.addstr(2+interval*i, 2, label, curses.A_REVERSE if self.popup_pos%numpos==i else 0)

            if buttons:
                w.addstr(5+interval*i, 10, "[  ok  ]", curses.A_REVERSE if self.popup_pos%numpos==(numpos-2) else curses.color_pair(2))
                w.addstr(5+interval*i, 25, "[cancel]", curses.A_REVERSE if self.popup_pos%numpos==(numpos-1) else curses.color_pair(2))

            w.refresh()

            c = self.getch()
            if c in [ord('q'), KEY_ESC]:
                break
            elif c in [curses.KEY_LEFT, curses.KEY_UP]:
                self.popup_pos -= 1
            elif c in [curses.KEY_RIGHT, curses.KEY_DOWN]:
                self.popup_pos +=1
            else:
                i = self.popup_pos%numpos
                if buttons and c == ord("\n"):
                    if i == numpos-2:
                        return out
                    elif i == numpos -1:
                        return {}

                item = items[i]
                _type = item.get('type')

                if _type == 'str':
                    item['value'] = self.edit_str(item['value'], c)
                    out[item.get('label')] = item.get('value')

                elif _type == 'password':
                    item['value'] = self.edit_str(item['value'], c)
                    out[item.get('label')] = item ['value']

                elif _type == 'satoshis':
                    item['value'] = self.edit_str(item['value'], c, True)
                    out[item.get('label')] = item.get('value')

                elif _type == 'list':
                    choices = item.get('choices')
                    try:
                        j = choices.index(item.get('value'))
                    except Exception:
                        j = 0
                    new_choice = choices[(j + 1)% len(choices)]
                    item['value'] = new_choice
                    out[item.get('label')] = item.get('value')

                elif _type == 'button':
                    out['button'] = item.get('label')
                    break
        return out

    def print_textbox(self, w, y, x, _text, highlighted):
        width = 60
        for i in range(len(_text)//width + 1):
            s = _text[i*width:(i+1)*width]
            w.addstr(y+i, x, s, curses.A_REVERSE if highlighted else curses.A_NORMAL)
        return i

    def show_request(self, key):
        req = self.wallet.get_request(key)
        addr = req.get_address() or ''
        URI = self.wallet.get_request_URI(req) or ''
        lnaddr = self.wallet.get_bolt11_invoice(req) or ''
        w = curses.newwin(self.maxy - 2, self.maxx - 2, 1, 1)
        pos = 4
        while True:
            if pos == 1:
                text = URI
                data = URI
            elif pos == 2:
                text = lnaddr
                data = lnaddr.upper()
            else:
                text = addr
                data = addr

            w.clear()
            w.border(0)
            w.addstr(0, 2, ' ' + _('Payment Request') + ' ')
            y = 2
            w.addstr(y, 2, "Address")
            h1 = self.print_textbox(w, y, 13, addr, pos==0)
            y += h1 + 2
            w.addstr(y, 2, "URI")
            h2 = self.print_textbox(w, y, 13, URI, pos==1)
            y += h2 + 2
            w.addstr(y, 2, "Lightning")
            h3 = self.print_textbox(w, y, 13, lnaddr, pos==2)
            y += h3 + 2
            lines = self.get_qr(data)
            qr_width = len(lines) * 2
            x = self.maxx - qr_width
            if x > 60:
                self.print_qr(w, 1, x, lines)
            else:
                w.addstr(y, 35, "(Window too small for QR code)")
            w.addstr(y, 13, "[Delete]", curses.A_REVERSE if pos==3 else curses.color_pair(2))
            w.addstr(y, 25, "[Close]", curses.A_REVERSE if pos==4 else curses.color_pair(2))
            w.refresh()
            c = self.getch()
            if c in [curses.KEY_UP]:
                pos -= 1
            elif c in [curses.KEY_DOWN, ord("\t")]:
                pos += 1
            elif c == ord("\n"):
                if pos in [0,1,2]:
                    pyperclip.copy(text)
                    self.show_message('Text copied to clipboard')
                elif pos == 3:
                    if self.question("Delete Request?"):
                        self.wallet.delete_request(key)
                        self.max_pos -= 1
                        break
                elif pos ==4:
                    break
            else:
                break
            pos = pos % 5
        self.stdscr.refresh()
        return
