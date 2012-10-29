import curses, datetime
from decimal import Decimal
from util import format_satoshis, set_verbosity

WIDTH=150

class ElectrumGui:

    def __init__(self, wallet, config, app=None):
        self.wallet = wallet
        self.config = config
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.start_color()
        self.stdscr.keypad(1)
        self.stdscr.border(0)
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        set_verbosity(False)
        self.tab = 0
        
    def server_list_changed(self):
        pass

    def restore_or_create(self):
        pass

    def print_history(self):
        b = 0 
        messages = []
        for line in self.wallet.get_tx_history():
            v = line['value'] 
            b += v
            try:
                time_str = str( datetime.datetime.fromtimestamp( line['timestamp']))
            except:
                print line['timestamp']
                time_str = 'pending'
            label = line.get('label')
            if not label: label = line['tx_hash']
            else: label = label + ' '*(64 - len(label) )
            messages.append( time_str + "  " + label + "  " + format_satoshis(v)+ "  "+ format_satoshis(b) )

        self.print_list(messages, "%19s  %64s %14s %10s"%("Date", "Description", "Amount", "Balance"))


    def print_balance(self):
        c, u =  self.wallet.get_balance()
        msg = "Balance: %f"%(Decimal( c ) / 100000000)
        if u:
            msg += "  [%f unconfirmed]"%(Decimal( u ) / 100000000)
        self.stdscr.addstr( self.maxy -3, 2, msg)

        tab_names = ["History", "Send", "Receive", "Contacts"]
        for i in range(4):
            self.stdscr.addstr( 0, 2+9*i, tab_names[i], curses.A_BOLD if self.tab == i else 0)
            
        self.stdscr.addstr( self.maxy -1, self.maxx-30, " Settings Network Quit ")

        

    def print_contacts(self):
        messages = map(lambda addr: "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"")), self.wallet.addressbook)
        self.print_list(messages, "%19s  %25s "%("Address", "Label"))

    def print_receive(self):
        messages = map(lambda addr: "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"")), self.wallet.addresses)
        self.print_list(messages, "%19s  %25s "%("Address", "Label"))

    def print_send_dialog(self):
        self.stdscr.clear()
        self.stdscr.addstr( 3, 2, "Pay to")
        self.stdscr.addstr( 5, 2, "Description")
        self.stdscr.addstr( 7, 2, "Amount")
        self.stdscr.addstr( 9, 2, "Fee")
        return
        
        while True:
            curses.echo()
            s = self.stdscr.getstr(3, 15)
            curses.noecho()

            if s: break
        pass


    def print_list(self, list, firstline):
        firstline += " "*(self.maxx -2 - len(firstline))
        self.stdscr.addstr( 1, 1, firstline )
        for i in range(self.maxy-6):
            msg = list[i] if i < len(list) else ""
            msg += " "*(self.maxx -2 - len(msg))
            self.stdscr.addstr( i+2, 1, msg[0:self.maxx - 2])

    def refresh(self):
        self.stdscr.border(0)
        self.print_balance()
        self.stdscr.refresh()

    def main(self,url):
        self.print_history()
        self.refresh()

        while 1:
            c = self.stdscr.getch()
            if c == curses.KEY_RIGHT: self.tab = (self.tab + 1)%4
            if c == curses.KEY_LEFT: self.tab = (self.tab - 1)%4
            elif c == ord('h'): self.tab = 0
            elif c == ord('s'): self.tab = 1
            elif c == ord('r'): self.tab = 2
            elif c == ord('c'): self.tab = 3
            elif c == ord('q'): break
            elif c == curses.KEY_HOME: x = y = 0

            if self.tab == 0:
                self.print_history()
            elif self.tab == 1:
                self.print_send_dialog()
            elif self.tab == 2:
                self.print_receive()
            else:
                self.print_contacts()
            self.refresh()

        curses.nocbreak();
        self.stdscr.keypad(0);
        curses.echo()            
        curses.endwin()

