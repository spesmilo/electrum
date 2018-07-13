import tty, sys
import curses, datetime, locale
from decimal import Decimal
import getpass

import electrum_ltc as electrum
from electrum_ltc.util import format_satoshis, set_verbosity
from electrum_ltc.bitcoin import is_address, COIN, TYPE_ADDRESS
from .. import Wallet, WalletStorage

_ = lambda x:x



class ElectrumGui:

    def __init__(self, config, daemon, plugins):

        self.config = config
        self.network = daemon.network
        storage = WalletStorage(config.get_wallet_path())
        if not storage.file_exists():
            print("Wallet not found. try 'electrum-ltc create'")
            exit()
        if storage.is_encrypted():
            password = getpass.getpass('Password:', stream=None)
            storage.decrypt(password)
        self.wallet = Wallet(storage)
        self.wallet.start_threads(self.network)
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
        self.stdscr.keypad(1)
        self.stdscr.border(0)
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        self.set_cursor(0)
        self.w = curses.newwin(10, 50, 5, 5)

        set_verbosity(False)
        self.tab = 0
        self.pos = 0
        self.popup_pos = 0

        self.str_recipient = ""
        self.str_description = ""
        self.str_amount = ""
        self.str_fee = ""
        self.history = None

        if self.network:
            self.network.register_callback(self.update, ['updated'])

        self.tab_names = [_("History"), _("Send"), _("Receive"), _("Addresses"), _("Contacts"), _("Banner")]
        self.num_tabs = len(self.tab_names)


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
        self.stdscr.addstr( y, x, " "*20, curses.A_REVERSE)
        s = self.stdscr.getstr(y,x)
        curses.noecho()
        self.set_cursor(0)
        return s

    def update(self, event):
        self.update_history()
        if self.tab == 0:
            self.print_history()
        self.refresh()

    def print_history(self):

        width = [20, 40, 14, 14]
        delta = (self.maxx - sum(width) - 4)/3
        format_str = "%"+"%d"%width[0]+"s"+"%"+"%d"%(width[1]+delta)+"s"+"%"+"%d"%(width[2]+delta)+"s"+"%"+"%d"%(width[3]+delta)+"s"

        if self.history is None:
            self.update_history()

        self.print_list(self.history[::-1], format_str%( _("Date"), _("Description"), _("Amount"), _("Balance")))

    def update_history(self):
        width = [20, 40, 14, 14]
        delta = (self.maxx - sum(width) - 4)/3
        format_str = "%"+"%d"%width[0]+"s"+"%"+"%d"%(width[1]+delta)+"s"+"%"+"%d"%(width[2]+delta)+"s"+"%"+"%d"%(width[3]+delta)+"s"

        b = 0
        self.history = []
        for item in self.wallet.get_history():
            tx_hash, height, conf, timestamp, value, balance = item
            if conf:
                try:
                    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = "------"
            else:
                time_str = 'unconfirmed'

            label = self.wallet.get_label(tx_hash)
            if len(label) > 40:
                label = label[0:37] + '...'
            self.history.append( format_str%( time_str, label, format_satoshis(value, whitespaces=True), format_satoshis(balance, whitespaces=True) ) )


    def print_balance(self):
        if not self.network:
            msg = _("Offline")
        elif self.network.is_connected():
            if not self.wallet.up_to_date:
                msg = _("Synchronizing...")
            else:
                c, u, x =  self.wallet.get_balance()
                msg = _("Balance")+": %f  "%(Decimal(c) / COIN)
                if u:
                    msg += "  [%f unconfirmed]"%(Decimal(u) / COIN)
                if x:
                    msg += "  [%f unmatured]"%(Decimal(x) / COIN)
        else:
            msg = _("Not connected")

        self.stdscr.addstr( self.maxy -1, 3, msg)

        for i in range(self.num_tabs):
            self.stdscr.addstr( 0, 2 + 2*i + len(''.join(self.tab_names[0:i])), ' '+self.tab_names[i]+' ', curses.A_BOLD if self.tab == i else 0)

        self.stdscr.addstr(self.maxy -1, self.maxx-30, ' '.join([_("Settings"), _("Network"), _("Quit")]))

    def print_receive(self):
        addr = self.wallet.get_receiving_address()
        self.stdscr.addstr(2, 1, "Address: "+addr)
        self.print_qr(addr)

    def print_contacts(self):
        messages = map(lambda x: "%20s   %45s "%(x[0], x[1][1]), self.contacts.items())
        self.print_list(messages, "%19s  %15s "%("Key", "Value"))

    def print_addresses(self):
        fmt = "%-35s  %-30s"
        messages = map(lambda addr: fmt % (addr, self.wallet.labels.get(addr,"")), self.wallet.get_addresses())
        self.print_list(messages,   fmt % ("Address", "Label"))

    def print_edit_line(self, y, label, text, index, size):
        text += " "*(size - len(text) )
        self.stdscr.addstr( y, 2, label)
        self.stdscr.addstr( y, 15, text, curses.A_REVERSE if self.pos%6==index else curses.color_pair(1))

    def print_send_tab(self):
        self.stdscr.clear()
        self.print_edit_line(3, _("Pay to"), self.str_recipient, 0, 40)
        self.print_edit_line(5, _("Description"), self.str_description, 1, 40)
        self.print_edit_line(7, _("Amount"), self.str_amount, 2, 15)
        self.print_edit_line(9, _("Fee"), self.str_fee, 3, 15)
        self.stdscr.addstr( 12, 15, _("[Send]"), curses.A_REVERSE if self.pos%6==4 else curses.color_pair(2))
        self.stdscr.addstr( 12, 25, _("[Clear]"), curses.A_REVERSE if self.pos%6==5 else curses.color_pair(2))
        self.maxpos = 6

    def print_banner(self):
        if self.network:
            self.print_list( self.network.banner.split('\n'))

    def print_qr(self, data):
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
        for i, l in enumerate(lines):
            l = l.encode("utf-8")
            self.stdscr.addstr(i+5, 5, l, curses.color_pair(3))

    def print_list(self, lst, firstline = None):
        lst = list(lst)
        self.maxpos = len(lst)
        if not self.maxpos: return
        if firstline:
            firstline += " "*(self.maxx -2 - len(firstline))
            self.stdscr.addstr( 1, 1, firstline )
        for i in range(self.maxy-4):
            msg = lst[i] if i < len(lst) else ""
            msg += " "*(self.maxx - 2 - len(msg))
            m = msg[0:self.maxx - 2]
            m = m.encode(self.encoding)
            self.stdscr.addstr( i+2, 1, m, curses.A_REVERSE if i == (self.pos % self.maxpos) else 0)

    def refresh(self):
        if self.tab == -1: return
        self.stdscr.border(0)
        self.print_balance()
        self.stdscr.refresh()

    def main_command(self):
        c = self.stdscr.getch()
        print(c)
        cc = curses.unctrl(c).decode()
        if   c == curses.KEY_RIGHT: self.tab = (self.tab + 1)%self.num_tabs
        elif c == curses.KEY_LEFT: self.tab = (self.tab - 1)%self.num_tabs
        elif c == curses.KEY_DOWN: self.pos +=1
        elif c == curses.KEY_UP: self.pos -= 1
        elif c == 9: self.pos +=1 # tab
        elif cc in ['^W', '^C', '^X', '^Q']: self.tab = -1
        elif cc in ['^N']: self.network_dialog()
        elif cc == '^S': self.settings_dialog()
        else: return c
        if self.pos<0: self.pos=0
        if self.pos>=self.maxpos: self.pos=self.maxpos - 1

    def run_tab(self, i, print_func, exec_func):
        while self.tab == i:
            self.stdscr.clear()
            print_func()
            self.refresh()
            c = self.main_command()
            if c: exec_func(c)


    def run_history_tab(self, c):
        if c == 10:
            out = self.run_popup('',["blah","foo"])


    def edit_str(self, target, c, is_num=False):
        # detect backspace
        cc = curses.unctrl(c).decode()
        if c in [8, 127, 263] and target:
            target = target[:-1]
        elif not is_num or cc in '0123456789.':
            target += cc
        return target


    def run_send_tab(self, c):
        if self.pos%6 == 0:
            self.str_recipient = self.edit_str(self.str_recipient, c)
        if self.pos%6 == 1:
            self.str_description = self.edit_str(self.str_description, c)
        if self.pos%6 == 2:
            self.str_amount = self.edit_str(self.str_amount, c, True)
        elif self.pos%6 == 3:
            self.str_fee = self.edit_str(self.str_fee, c, True)
        elif self.pos%6==4:
            if c == 10: self.do_send()
        elif self.pos%6==5:
            if c == 10: self.do_clear()


    def run_receive_tab(self, c):
        if c == 10:
            out = self.run_popup('Address', ["Edit label", "Freeze", "Prioritize"])

    def run_contacts_tab(self, c):
        if c == 10 and self.contacts:
            out = self.run_popup('Address', ["Copy", "Pay to", "Edit label", "Delete"]).get('button')
            key = list(self.contacts.keys())[self.pos%len(self.contacts.keys())]
            if out == "Pay to":
                self.tab = 1
                self.str_recipient = key
                self.pos = 2
            elif out == "Edit label":
                s = self.get_string(6 + self.pos, 18)
                if s:
                    self.wallet.labels[key] = s

    def run_banner_tab(self, c):
        self.show_message(repr(c))
        pass

    def main(self):

        tty.setraw(sys.stdin)
        while self.tab != -1:
            self.run_tab(0, self.print_history, self.run_history_tab)
            self.run_tab(1, self.print_send_tab, self.run_send_tab)
            self.run_tab(2, self.print_receive, self.run_receive_tab)
            self.run_tab(3, self.print_addresses, self.run_banner_tab)
            self.run_tab(4, self.print_contacts, self.run_contacts_tab)
            self.run_tab(5, self.print_banner, self.run_banner_tab)

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

    def do_send(self):
        if not is_address(self.str_recipient):
            self.show_message(_('Invalid Litecoin address'))
            return
        try:
            amount = int(Decimal(self.str_amount) * COIN)
        except Exception:
            self.show_message(_('Invalid Amount'))
            return
        try:
            fee = int(Decimal(self.str_fee) * COIN)
        except Exception:
            self.show_message(_('Invalid Fee'))
            return

        if self.wallet.has_password():
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None
        try:
            tx = self.wallet.mktx([(TYPE_ADDRESS, self.str_recipient, amount)], password, self.config, fee)
        except Exception as e:
            self.show_message(str(e))
            return

        if self.str_description:
            self.wallet.labels[tx.txid()] = self.str_description

        self.show_message(_("Please wait..."), getchar=False)
        status, msg = self.network.broadcast_transaction(tx)

        if status:
            self.show_message(_('Payment sent.'))
            self.do_clear()
            #self.update_contacts_tab()
        else:
            self.show_message(_('Error'))


    def show_message(self, message, getchar = True):
        w = self.w
        w.clear()
        w.border(0)
        for i, line in enumerate(message.split('\n')):
            w.addstr(2+i,2,line)
        w.refresh()
        if getchar: c = self.stdscr.getch()

    def run_popup(self, title, items):
        return self.run_dialog(title, list(map(lambda x: {'type':'button','label':x}, items)), interval=1, y_pos = self.pos+3)

    def network_dialog(self):
        if not self.network:
            return
        params = self.network.get_parameters()
        host, port, protocol, proxy_config, auto_connect = params
        srv = 'auto-connect' if auto_connect else self.network.default_server
        out = self.run_dialog('Network', [
            {'label':'server', 'type':'str', 'value':srv},
            {'label':'proxy', 'type':'str', 'value':self.config.get('proxy', '')},
            ], buttons = 1)
        if out:
            if out.get('server'):
                server = out.get('server')
                auto_connect = server == 'auto-connect'
                if not auto_connect:
                    try:
                        host, port, protocol = server.split(':')
                    except Exception:
                        self.show_message("Error:" + server + "\nIn doubt, type \"auto-connect\"")
                        return False
            if out.get('server') or out.get('proxy'):
                proxy = electrum.network.deserialize_proxy(out.get('proxy')) if out.get('proxy') else proxy_config
                self.network.set_parameters(host, port, protocol, proxy, auto_connect)

    def settings_dialog(self):
        fee = str(Decimal(self.config.fee_per_kb()) / COIN)
        out = self.run_dialog('Settings', [
            {'label':'Default fee', 'type':'satoshis', 'value': fee }
            ], buttons = 1)
        if out:
            if out.get('Default fee'):
                fee = int(Decimal(out['Default fee']) * COIN)
                self.config.set_key('fee_per_kb', fee, True)


    def password_dialog(self):
        out = self.run_dialog('Password', [
            {'label':'Password', 'type':'password', 'value':''}
            ], buttons = 1)
        return out.get('Password')


    def run_dialog(self, title, items, interval=2, buttons=None, y_pos=3):
        self.popup_pos = 0

        self.w = curses.newwin( 5 + len(list(items))*interval + (2 if buttons else 0), 50, y_pos, 5)
        w = self.w
        out = {}
        while True:
            w.clear()
            w.border(0)
            w.addstr( 0, 2, title)

            num = len(list(items))

            numpos = num
            if buttons: numpos += 2

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
                    w.addstr( 2+interval*i, 2, label)
                    w.addstr( 2+interval*i, 15, value, curses.A_REVERSE if self.popup_pos%numpos==i else curses.color_pair(1) )
                else:
                    w.addstr( 2+interval*i, 2, label, curses.A_REVERSE if self.popup_pos%numpos==i else 0)

            if buttons:
                w.addstr( 5+interval*i, 10, "[  ok  ]", curses.A_REVERSE if self.popup_pos%numpos==(numpos-2) else curses.color_pair(2))
                w.addstr( 5+interval*i, 25, "[cancel]", curses.A_REVERSE if self.popup_pos%numpos==(numpos-1) else curses.color_pair(2))

            w.refresh()

            c = self.stdscr.getch()
            if c in [ord('q'), 27]: break
            elif c in [curses.KEY_LEFT, curses.KEY_UP]: self.popup_pos -= 1
            elif c in [curses.KEY_RIGHT, curses.KEY_DOWN]: self.popup_pos +=1
            else:
                i = self.popup_pos%numpos
                if buttons and c==10:
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
