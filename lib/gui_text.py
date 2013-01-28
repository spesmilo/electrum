import curses, datetime
from decimal import Decimal
_ = lambda x:x
#from i18n import _
from util import format_satoshis, set_verbosity

import tty, sys


class ElectrumGui:

    def __init__(self, wallet, config, app=None):
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_CYAN)
        self.stdscr.keypad(1)
        self.stdscr.border(0)
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        curses.curs_set(0)
        self.w = curses.newwin(10, 50, 5, 5)

        self.wallet = wallet
        self.config = config
        set_verbosity(False)
        self.tab = 0
        self.pos = 0
        self.popup_pos = 0

        self.str_recipient = ""
        self.str_description = ""
        self.str_amount = ""
        self.str_fee = ""
        
        self.wallet.interface.register_callback('updated', self.refresh)
        self.wallet.interface.register_callback('connected', self.refresh)
        self.wallet.interface.register_callback('disconnected', self.refresh)
        self.wallet.interface.register_callback('disconnecting', self.refresh)
        self.tab_names = [_("History"), _("Send"), _("Receive"), _("Contacts"), _("Wall")]
        self.num_tabs = len(self.tab_names)
        

    def restore_or_create(self):
        pass


    def get_string(self, y, x):
        curses.curs_set(1)
        curses.echo()
        self.stdscr.addstr( y, x, " "*20, curses.A_REVERSE)
        s = self.stdscr.getstr(y,x)
        curses.noecho()
        curses.curs_set(0)
        return s


    def print_history(self):
        width = [20, 40, 14, 14]
        delta = (self.maxx - sum(width) - 4)/3
        format_str = "%"+"%d"%width[0]+"s"+"%"+"%d"%(width[1]+delta)+"s"+"%"+"%d"%(width[2]+delta)+"s"+"%"+"%d"%(width[3]+delta)+"s"

        b = 0 
        messages = []

        for item in self.wallet.get_tx_history():
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            if conf:
                try:
                    time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
                except:
                    time_str = "------"
            else:
                time_str = 'pending'

            label, is_default_label = self.wallet.get_label(tx_hash)
            messages.append( format_str%( time_str, label, format_satoshis(value), format_satoshis(balance) ) )

        self.print_list(messages[::-1], format_str%( _("Date"), _("Description"), _("Amount"), _("Balance")))


    def print_balance(self):
        if self.wallet.interface and self.wallet.interface.is_connected:
            if not self.wallet.up_to_date:
                msg = _( "Synchronizing..." )
            else: 
                c, u =  self.wallet.get_balance()
                msg = _("Balance")+": %f  "%(Decimal( c ) / 100000000)
                if u: msg += "  [%f unconfirmed]"%(Decimal( u ) / 100000000)
        else:
                msg = _( "Not connected" )
            
        self.stdscr.addstr( self.maxy -1, 3, msg)

        for i in range(self.num_tabs):
            self.stdscr.addstr( 0, 2 + 2*i + len(''.join(self.tab_names[0:i])), ' '+self.tab_names[i]+' ', curses.A_BOLD if self.tab == i else 0)
            
        self.stdscr.addstr( self.maxy -1, self.maxx-30, ' '.join([_("Settings"), _("Network"), _("Quit")]))


    def print_contacts(self):
        messages = map(lambda addr: "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"")), self.wallet.addressbook)
        self.print_list(messages, "%19s  %25s "%("Address", "Label"))

    def print_receive(self):
        messages = map(lambda addr: "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"")), self.wallet.addresses)
        self.print_list(messages, "%19s  %25s "%("Address", "Label"))

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

    def print_banner(self):
        self.stdscr.addstr( 1, 1, self.wallet.banner )

    def print_list(self, list, firstline):
        self.maxpos = len(list)
        if not self.maxpos: return
        firstline += " "*(self.maxx -2 - len(firstline))
        self.stdscr.addstr( 1, 1, firstline )
        for i in range(self.maxy-4):
            msg = list[i] if i < len(list) else ""
            msg += " "*(self.maxx - 2 - len(msg))
            self.stdscr.addstr( i+2, 1, msg[0:self.maxx - 2], curses.A_REVERSE if i == (self.pos % self.maxpos) else 0)

    def refresh(self):
        if self.tab == -1: return
        self.stdscr.border(0)
        self.print_balance()
        self.stdscr.refresh()

    def main_command(self):
        c = self.stdscr.getch()
        print c
        if   c == curses.KEY_RIGHT: self.tab = (self.tab + 1)%self.num_tabs
        elif c == curses.KEY_LEFT: self.tab = (self.tab - 1)%self.num_tabs
        elif c == curses.KEY_DOWN: self.pos +=1
        elif c == curses.KEY_UP: self.pos -= 1
        elif c == 9: self.pos +=1 # tab
        elif curses.unctrl(c) in ['^W', '^C', '^X', '^Q']: self.tab = -1
        elif curses.unctrl(c) in ['^N']: self.network_dialog()
        elif curses.unctrl(c) == '^S': self.settings_dialog()
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
        if c==263 and target:
            target = target[:-1]
        elif not is_num or curses.unctrl(c) in '0123456789.':
            target += curses.unctrl(c)
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
        if c == 10:
            out = self.run_popup('Adress', ["Copy", "Pay to", "Edit label", "Delete"]).get('button')
            address = self.wallet.addressbook[self.pos%len(self.wallet.addressbook)]
            if out == "Pay to":
                self.tab = 1
                self.str_recipient = address 
                self.pos = 2
            elif out == "Edit label":
                s = self.get_string(6 + self.pos, 18)
                if s:
                    self.wallet.labels[address] = s
            
    def run_banner_tab(self, c):
        self.show_message(repr(c))
        pass

    def main(self,url):

        tty.setraw(sys.stdin)
        while self.tab != -1:
            self.run_tab(0, self.print_history, self.run_history_tab)
            self.run_tab(1, self.print_send_tab, self.run_send_tab)
            self.run_tab(2, self.print_receive, self.run_receive_tab)
            self.run_tab(3, self.print_contacts, self.run_contacts_tab)
            self.run_tab(4, self.print_banner, self.run_banner_tab)

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
        if not self.wallet.is_valid(self.str_recipient):
            self.show_message(_('Invalid Bitcoin address'))
            return
        try:
            amount = int( Decimal( self.str_amount) * 100000000 )
        except:
            self.show_message(_('Invalid Amount'))
            return
        try:
            fee = int( Decimal( self.str_fee) * 100000000 )
        except:
            self.show_message(_('Invalid Fee'))
            return

        if self.wallet.use_encryption:
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None

        try:
            tx = self.wallet.mktx( [(self.str_recipient, amount)], self.str_description, password, fee)
        except BaseException, e:
            self.show_message(str(e))
            return
            
        h = self.wallet.send_tx(tx)
        self.show_message(_("Please wait..."), getchar=False)
        self.wallet.tx_event.wait()
        status, msg = self.wallet.receive_tx( h )

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
        w.addstr(2,2,message)
        w.refresh()
        if getchar: c = self.stdscr.getch()


    def run_popup(self, title, items):
        return self.run_dialog(title, map(lambda x: {'type':'button','label':x}, items), interval=1, y_pos = self.pos+3)


    def network_dialog(self):
        out = self.run_dialog('Network', [
            {'label':'server', 'type':'str', 'value':self.wallet.interface.server},
            {'label':'proxy', 'type':'str', 'value':self.config.get('proxy', '')},
            ], buttons = 1)
        if out:
            if out.get('server'):
                server = out.get('server')
                if out.get('proxy'):
                    proxy = self.parse_proxy_options(out.get('proxy'))
                else:
                    proxy = None

                self.wallet.config.set_key("proxy", proxy, True)
                self.wallet.config.set_key("server", server, True)
                self.wallet.interface.set_server(server, proxy)
                


    def settings_dialog(self):
        out = self.run_dialog('Settings', [
            {'label':'Default GUI', 'type':'list', 'choices':['classic','lite','gtk','text'], 'value':self.config.get('gui')},
            {'label':'Default fee', 'type':'satoshis', 'value': format_satoshis(self.config.get('fee')).strip() }
            ], buttons = 1)
        if out:
            if out.get('Default GUI'):
                self.config.set_key('gui', out['Default GUI'], True)
            if out.get('Default fee'):
                fee = int ( Decimal( out['Default fee']) *10000000 )
                self.config.set_key('fee', fee, True)


    def password_dialog(self):
        out = self.run_dialog('Password', [
            {'label':'Password', 'type':'password', 'value':''}
            ], buttons = 1)
        return out.get('Password')
        

    def run_dialog(self, title, items, interval=2, buttons=None, y_pos=3):
        self.popup_pos = 0
        
        self.w = curses.newwin( 5 + len(items)*interval + (2 if buttons else 0), 50, y_pos, 5)
        w = self.w
        out = {}
        while True:
            w.clear()
            w.border(0)
            w.addstr( 0, 2, title)

            num = len(items)

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

                if len(value)<20: value += ' '*(20-len(value))

                if item.has_key('value'):
                    w.addstr( 2+interval*i, 2, label)
                    w.addstr( 2+interval*i, 15, value, curses.A_REVERSE if self.popup_pos%numpos==i else curses.color_pair(1) )
                else:
                    w.addstr( 2+interval*i, 2, label, curses.A_REVERSE if self.popup_pos%numpos==i else 0)

            if buttons:
                w.addstr( 5+interval*i, 10, "[  ok  ]",     curses.A_REVERSE if self.popup_pos%numpos==(numpos-2) else curses.color_pair(2))
                w.addstr( 5+interval*i, 25, "[cancel]", curses.A_REVERSE if self.popup_pos%numpos==(numpos-1) else curses.color_pair(2))
                
            w.refresh()

            c = self.stdscr.getch()
            if c in [ord('q'), 27]: break
            elif c == curses.KEY_UP: self.popup_pos -= 1
            elif c == curses.KEY_DOWN: self.popup_pos +=1
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
                    except:
                        j = 0
                    new_choice = choices[(j + 1)% len(choices)]
                    item['value'] = new_choice
                    out[item.get('label')] = item.get('value')
                    
                elif _type == 'button':
                    out['button'] = item.get('label')
                    break

        return out

