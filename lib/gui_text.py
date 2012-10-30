import curses, datetime
from decimal import Decimal
_ = lambda x:x
#from i18n import _
from util import format_satoshis, set_verbosity



class ElectrumGui:

    def __init__(self, wallet, config, app=None):
        self.wallet = wallet
        self.config = config
        self.stdscr = curses.initscr()
        
        #c = self.stdscr.getch()
        #print c
        
        curses.noecho()
        curses.cbreak()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
        
        self.stdscr.keypad(1)
        self.stdscr.border(0)
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        set_verbosity(False)
        self.tab = 0
        self.pos = 0
        self.popup_pos = 0
        self.w = None

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
        curses.curs_set(0)
        if not self.w: self.w = curses.newwin(10, 50, 5, 5)
        
    def server_list_changed(self):
        pass

    def restore_or_create(self):
        pass

    def print_history(self):
        width = [20, 40, 14, 14]
        delta = (self.maxx - sum(width) - 4)/3
        format_str = "%"+"%d"%width[0]+"s"+"%"+"%d"%(width[1]+delta)+"s"+"%"+"%d"%(width[2]+delta)+"s"+"%"+"%d"%(width[3]+delta)+"s"

        b = 0 
        messages = []
        for tx in self.wallet.get_tx_history():
            v = tx['value'] 
            b += v
            try:
                time_str = str( datetime.datetime.fromtimestamp( tx['timestamp']))
            except:
                print tx['timestamp']
                time_str = 'pending'
            tx_hash = tx['tx_hash']

            label = self.wallet.labels.get(tx_hash)
            is_default_label = (label == '') or (label is None)
            if is_default_label: label = tx['default_label']

            #label += ' '*(40 - len(label) )
            messages.append( format_str%( time_str, label, format_satoshis(v), format_satoshis(b) ) )

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
            self.stdscr.addstr( 0, 2 + 2*i + len(''.join(self.tab_names[0:i])), self.tab_names[i], curses.A_BOLD if self.tab == i else 0)
            
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
        self.stdscr.addstr( y, 15, text, curses.A_REVERSE if self.pos%5==index else curses.color_pair(1))

    def print_send_tab(self):
        self.stdscr.clear()
        self.print_edit_line(3, _("Pay to"), self.str_recipient, 0, 40)
        self.print_edit_line(5, _("Description"), self.str_description, 1, 40)
        self.print_edit_line(7, _("Amount"), self.str_amount, 2, 15)
        self.print_edit_line(9, _("Fee"), self.str_fee, 3, 15)
        self.stdscr.addstr( 12, 15, _("Send"), curses.A_REVERSE if self.pos%5==4 else 0)

    def getstr_send(self):
        curses.curs_set(1)
        curses.echo()
        if self.pos%5==0:
            s = self.stdscr.getstr(3, 15)
            if s: self.str_recipient = s
        elif self.pos%5==1:
            s = self.stdscr.getstr(5, 15)
            if s: self.str_description = s
        elif self.pos%5==2:
            s = self.stdscr.getstr(7, 15)
            if s: self.str_amount = s
        elif self.pos%5==3:
            s = self.stdscr.getstr(9, 15)
            if s: self.str_fee = s
        else:
            pass
        curses.noecho()
        curses.curs_set(0)
        self.print_send_tab()

    def print_banner(self):
        self.stdscr.clear()
        self.stdscr.addstr( 1, 1, self.wallet.banner )

    def print_list(self, list, firstline):
        firstline += " "*(self.maxx -2 - len(firstline))
        self.stdscr.addstr( 1, 1, firstline )
        for i in range(self.maxy-4):
            msg = list[i] if i < len(list) else ""
            msg += " "*(self.maxx - 2 - len(msg))
            self.stdscr.addstr( i+2, 1, msg[0:self.maxx - 2], curses.A_REVERSE if i == (self.pos % len(list)) else 0)

    def refresh(self):
        self.stdscr.border(0)
        self.print_balance()
        self.stdscr.refresh()

    def main(self,url):
        self.print_history()
        self.refresh()

        while True:
            c = self.stdscr.getch()

            if   c == curses.KEY_RIGHT: self.tab = (self.tab + 1)%self.num_tabs
            elif c == curses.KEY_LEFT: self.tab = (self.tab - 1)%self.num_tabs
                
            elif c == curses.KEY_DOWN: self.pos +=1
            elif c == curses.KEY_UP: self.pos -= 1
            elif c == 9: self.pos +=1 # tab

            elif c in [27, ord('q')]: break
            elif c == 10: self.exec_popup()

            elif c == ord('n'): self.network_dialog()
            elif c == ord('s'): self.settings_dialog()

            if self.tab == 0:
                self.print_history()
            elif self.tab == 1:
                self.print_send_tab()
            elif self.tab == 2:
                self.print_receive()
            elif self.tab == 3:
                self.print_contacts()
            else:
                self.print_banner()
            self.refresh()

        curses.nocbreak();
        self.stdscr.keypad(0);
        curses.echo()            
        curses.endwin()


    def exec_popup(self):
        if self.tab == 0:
            out = self.run_popup('',["blah","foo"])
        elif self.tab == 1:
            if self.pos%5==4:
                self.do_send()
            else:
                self.getstr_send()
                self.print_send_tab()
        elif self.tab == 2:
            out = self.run_popup('', ["blah"])
        elif self.tab == 3:
            out = self.run_popup('', ["Pay to","Edit label"])
            if out == "Pay to":
                self.tab = 1
                self.str_recipient = self.wallet.addressbook[self.pos%len(self.wallet.addressbook)]
                self.pos = 2
                



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


    def show_message(self, message):
        w = self.w
        w.clear()
        w.border(0)
        w.addstr(2,2,message)
        w.refresh()
        c = self.stdscr.getch()


    def run_popup(self, text, items):
        "multiple choices"
        w = self.w
        while True:
            w.clear()
            w.border(0)
            w.addstr(2,2,text)
            for i in range(len(items)):
                item = items[i]
                w.addstr( 4 + i, 2, item, curses.A_REVERSE if self.popup_pos%(len(items))==i else 0)
            w.refresh()

            answer = False
            c = self.stdscr.getch()
            if c == 10:
                answer = True
                break
            elif c == 27:
                break
            elif c == curses.KEY_UP: self.popup_pos -= 1
            elif c == curses.KEY_DOWN: self.popup_pos +=1

        if answer: return items[self.popup_pos%(len(items))]


    def network_dialog(self):
        out = self.run_dialog('Network', [
            {'label':'server', 'type':'str', 'value':self.wallet.interface.server},
            {'label':'proxy', 'type':'str', 'value':self.config.get('proxy')},
            ])
        if out:
            if out.get('server'):  self.wallet.interface.set_server(out.get('server'))

    def settings_dialog(self):
        out = self.run_dialog('Settings', [
            {'label':'Default GUI', 'type':'list', 'choices':['classic','lite','gtk','text'], 'value':self.config.get('gui')},
            {'label':'Default fee', 'type':'satoshis', 'value':self.config.get('fee')}
            ])
        if out:
            if out.get('Default GUI'): self.config.set_key('gui', out['Default GUI'], True)

    def password_dialog(self):
        out = self.run_dialog('Password', [
            {'label':'Password', 'type':'str'}
            ])
        return out
        
                              


    def run_dialog(self, title, items):
        w = self.w
        #items.append({'label':'cancel','type':'button'})
        items.append({'label':' ok ','type':'button'})
        out = {}
        while True:
            w.clear()
            w.border(0)
            w.addstr( 0, 2, title)

            num = len(items)
            for i in range(num):
                item = items[i]
                label = item.get('label')
                if item.get('type') == 'list':
                    value = item.get('value','')
                elif item.get('type') == 'satoshis':
                    value = format_satoshis(item.get('value'))
                elif item.get('type') == 'str':
                    value = item.get('value','')
                else:
                    value = None
                if value:
                    w.addstr( 2+2*i, 2, label)
                    w.addstr( 2+2*i, 15, value, curses.A_REVERSE if self.popup_pos%num==i else curses.color_pair(1) )
                else:
                    w.addstr( 2+2*i, 15, label, curses.A_REVERSE if self.popup_pos%num==i else 0)
                
            w.refresh()

            c = self.stdscr.getch()
            if c in [ord('q'), 27]: break
            elif c == curses.KEY_UP: self.popup_pos -= 1
            elif c == curses.KEY_DOWN: self.popup_pos +=1
            elif c == 10:
                i = self.popup_pos%num
                item = items[i]
                _type = item.get('type')
                if _type == 'str':
                    curses.curs_set(1)
                    curses.echo()
                    s = w.getstr(2+2*i, 15)
                    curses.noecho()
                    curses.curs_set(0)
                    item['value'] = s
                    out[item.get('label')] = item.get('value')

                elif _type == 'satoshis':
                    curses.curs_set(1)
                    curses.echo()
                    s = w.getstr(2+2*i, 15)
                    curses.noecho()
                    curses.curs_set(0)
                    try:
                        s = int( Decimal(s)*100000000 )
                        item['value'] = s
                        out[item.get('label')] = item.get('value')
                    except:
                        pass
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
                    break

        
        return out




