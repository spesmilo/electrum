import curses, datetime
from decimal import Decimal
from electrum import format_satoshis


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
        
    def server_list_changed(self):
        pass

    def restore_or_create(self):
        pass

    def print_history(self):
        lines = self.wallet.get_tx_history()
        b = 0 
        i = 0
        for i in range(20):
            if i < len(lines):
                line = lines[i]
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
                msg = time_str + "  " + label + "  " + format_satoshis(v)+ "  "+ format_satoshis(b)
            else:
                msg = ""
        
            msg += " "*(WIDTH - len(msg))
            self.stdscr.addstr( i+2, 1, msg[0:WIDTH])

    def print_balance(self):
        c, u =  self.wallet.get_balance()
        msg = "Balance: %f %f"%(Decimal( c ) / 100000000 , Decimal( u ) / 100000000)
        self.stdscr.addstr( 22, 1, msg)
        self.stdscr.addstr( 24, 1, "History Send Receive Contacts Quit")

    def print_contacts(self):
        for i in range(20):
            if i < len(self.wallet.addressbook):
                addr = self.wallet.addressbook[i]
                msg = "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"") )
            else:
                msg = ""

            msg += " "*(WIDTH - len(msg))
            self.stdscr.addstr( i+2, 1, msg[0:WIDTH])

    def print_receive(self):
        for i in range(20):
            if i < len(self.wallet.addresses):
                addr = self.wallet.addresses[i]
                msg = "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"") )
            else:
                msg = ""
                
            msg += " "*(WIDTH - len(msg))
            self.stdscr.addstr( i+2, 1, msg[0:WIDTH])

    def refresh(self):
        self.print_balance()
        self.stdscr.refresh()

    def main(self,url):
        self.print_history()
        self.refresh()

        while 1:
            c = self.stdscr.getch()
            if c == ord('h'): self.print_history()
            if c == ord('c'): self.print_contacts()
            if c == ord('r'): self.print_receive()
            elif c == ord('q'): break
            elif c == curses.KEY_HOME: x = y = 0
            self.refresh()

        curses.nocbreak();
        self.stdscr.keypad(0);
        curses.echo()            
        curses.endwin()

