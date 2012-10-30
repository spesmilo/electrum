import curses, datetime
from decimal import Decimal
_ = lambda x:x
#from i18n import _
from util import format_satoshis, set_verbosity


EMPTY = " "*15

class ElectrumGui:

    def __init__(self, wallet, config, app=None):
        self.wallet = wallet
        self.config = config
        self.stdscr = curses.initscr()
        
        #c = self.stdscr.getch()
        #print c
        
        curses.noecho()
        curses.cbreak()
        #curses.start_color()
        self.stdscr.keypad(1)
        self.stdscr.border(0)
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        set_verbosity(False)
        self.tab = 0
        self.pos = 0
        self.popup_pos = 0
        self.w = None
        self.is_popup = False

        self.str_recipient = EMPTY
        self.str_description = EMPTY
        self.str_amount = EMPTY
        self.str_fee = EMPTY
        
        self.wallet.interface.register_callback('updated', self.refresh)
        self.wallet.interface.register_callback('connected', self.refresh)
        self.wallet.interface.register_callback('disconnected', self.refresh)
        self.wallet.interface.register_callback('disconnecting', self.refresh)
        self.tab_names = [_("History"), _("Send"), _("Receive"), _("Contacts"), _("Wall")]
        self.num_tabs = len(self.tab_names)
        curses.curs_set(0)
        
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

    def print_send_dialog(self):
        self.stdscr.clear()
        self.stdscr.addstr( 3, 2, _("Pay to"))
        self.stdscr.addstr( 3, 15, self.str_recipient, curses.A_REVERSE if self.pos%5==0 else 0)

        self.stdscr.addstr( 5, 2, _("Description"))
        self.stdscr.addstr( 5, 15, self.str_description, curses.A_REVERSE if self.pos%5==1 else 0)

        self.stdscr.addstr( 7, 2, _("Amount"))
        self.stdscr.addstr( 7, 15, self.str_amount, curses.A_REVERSE if self.pos%5==2 else 0)

        self.stdscr.addstr( 9, 2, _("Fee"))
        self.stdscr.addstr( 9, 15, self.str_fee, curses.A_REVERSE if self.pos%5==3 else 0)

        self.stdscr.addstr( 11, 15, _("Send"), curses.A_REVERSE if self.pos%5==4 else 0)

    def exec_send(self):
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
        self.print_send_dialog()

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

        self.is_popup = False
        while 1:
            c = self.stdscr.getch()

            if not self.is_popup:
                if   c == curses.KEY_RIGHT: self.tab = (self.tab + 1)%self.num_tabs
                elif c == curses.KEY_LEFT: self.tab = (self.tab - 1)%self.num_tabs
                elif c == ord('h'): self.tab = 0
                elif c == ord('s'): self.tab = 1
                elif c == ord('r'): self.tab = 2
                elif c == ord('c'): self.tab = 3

                elif c == curses.KEY_DOWN: self.pos +=1
                elif c == curses.KEY_UP: self.pos -= 1
                elif c == 9: self.pos +=1 # tab

                elif c in [27, ord('q')]: break
                elif c == 10: self.is_popup = True

                elif c == ord('n'): self.network_dialog()
                elif c == ord('s'): self.settings_dialog()

            else:
                if c == 10: self.is_popup = False
                elif c == 27: self.is_popup = False
                elif c == curses.KEY_UP: self.popup_pos -= 1
                elif c == curses.KEY_DOWN: self.popup_pos +=1
                #else: raise BaseException("zz %d"%c)

            if self.is_popup:
                if self.tab == 0:
                    self.context_popup('',["blah","foo"])
                elif self.tab == 1 and self.pos%5==4:
                    self.context_popup('Pay?',["Pay","Cancel"])
                elif self.tab == 2:
                    self.context_popup('', ["blah"])
                elif self.tab == 3:
                    self.context_popup('', ["Pay to"])
                else:
                    self.exec_send()
                    self.is_popup = False
                    #self.print_send_dialog()
                    
            else:
                if self.tab == 0:
                    self.print_history()
                elif self.tab == 1:
                    self.print_send_dialog()
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

    def context_popup(self, text, items):
        if not self.w: self.w = curses.newwin(10, 30, 5, 5)
        w = self.w
        w.clear()
        w.border(0)

        w.addstr( 2,2,text)
        
        for i in range(len(items)):
            item = items[i]
            w.addstr( 4 + 2*i, 2, item, curses.A_REVERSE if self.popup_pos%(len(items))==i else 0)
            

        w.refresh()

    def network_dialog(self):
        pass

    def settings_dialog(self):
        pass
