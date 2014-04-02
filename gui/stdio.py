from decimal import Decimal
_ = lambda x:x
#from i18n import _
from electrum import mnemonic_encode, WalletStorage, Wallet
from electrum.util import format_satoshis, set_verbosity
from electrum.bitcoin import is_valid
from electrum.network import filter_protocol
import sys, getpass, datetime

# minimal fdisk like gui for console usage
# written by rofl0r, with some bits stolen from the text gui (ncurses)

class ElectrumGui:

    def __init__(self, config, network):
        self.network = network
        self.config = config
        storage = WalletStorage(config)
        if not storage.file_exists:
            print "Wallet not found. try 'electrum create'"
            exit()

	self.done = 0
        self.last_balance = ""

        set_verbosity(False)

        self.str_recipient = ""
        self.str_description = ""
        self.str_amount = ""
        self.str_fee = ""

        self.wallet = Wallet(storage)
        self.wallet.start_threads(network)
        
        self.wallet.network.register_callback('updated', self.updated)
        self.wallet.network.register_callback('connected', self.connected)
        self.wallet.network.register_callback('disconnected', self.disconnected)
        self.wallet.network.register_callback('disconnecting', self.disconnecting)
        self.wallet.network.register_callback('peers', self.peers)
        self.wallet.network.register_callback('banner', self.print_banner)
        self.commands = [_("[h] - displays this help text"), \
                         _("[i] - display transaction history"), \
                         _("[o] - enter payment order"), \
                         _("[p] - print stored payment order"), \
                         _("[s] - send stored payment order"), \
                         _("[r] - show own receipt addresses"), \
                         _("[c] - display contacts"), \
                         _("[b] - print server banner"), \
                         _("[q] - quit") ]
        self.num_commands = len(self.commands)

    def main_command(self):
        self.print_balance()
        c = raw_input("enter command: ")
        if   c == "h" : self.print_commands()
        elif c == "i" : self.print_history()
        elif c == "o" : self.enter_order()
        elif c == "p" : self.print_order()
        elif c == "s" : self.send_order()
        elif c == "r" : self.print_addresses()
        elif c == "c" : self.print_contacts()
        elif c == "b" : self.print_banner()
        elif c == "n" : self.network_dialog()
        elif c == "e" : self.settings_dialog()
        elif c == "q" : self.done = 1
        else: self.print_commands()

    def peers(self):
        print("got peers list:")
        l = filter_protocol(self.wallet.network.get_servers(), 's')
        for s in l:
            print (s)

    def connected(self):
        print ("connected")

    def disconnected(self):
        print ("disconnected")

    def disconnecting(self):
        print ("disconnecting")

    def updated(self):
        s = self.get_balance()
        if s != self.last_balance:
            print(s)
        self.last_balance = s
        return True

    def print_commands(self):
        self.print_list(self.commands, "Available commands")

    def print_history(self):
        width = [20, 40, 14, 14]
        delta = (80 - sum(width) - 4)/3
        format_str = "%"+"%d"%width[0]+"s"+"%"+"%d"%(width[1]+delta)+"s"+"%" \
        + "%d"%(width[2]+delta)+"s"+"%"+"%d"%(width[3]+delta)+"s"
        b = 0 
        messages = []

        for item in self.wallet.get_tx_history():
            tx_hash, confirmations, is_mine, value, fee, balance, timestamp = item
            if confirmations:
                try:
                    time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = "unknown"
            else:
                time_str = 'pending'

            label, is_default_label = self.wallet.get_label(tx_hash)
            messages.append( format_str%( time_str, label, format_satoshis(value, whitespaces=True), format_satoshis(balance, whitespaces=True) ) )

        self.print_list(messages[::-1], format_str%( _("Date"), _("Description"), _("Amount"), _("Balance")))


    def print_balance(self):
        print(self.get_balance())

    def get_balance(self):
        if self.wallet.network.interface and self.wallet.network.interface.is_connected:
            if not self.wallet.up_to_date:
                msg = _( "Synchronizing..." )
            else: 
                c, u =  self.wallet.get_balance()
                msg = _("Balance")+": %f  "%(Decimal( c ) / 100000000)
                if u: msg += "  [%f unconfirmed]"%(Decimal( u ) / 100000000)
        else:
                msg = _( "Not connected" )
            
        return(msg)


    def print_contacts(self):
        messages = map(lambda addr: "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"")), self.wallet.addressbook)
        self.print_list(messages, "%19s  %25s "%("Address", "Label"))

    def print_addresses(self):
        messages = map(lambda addr: "%30s    %30s       "%(addr, self.wallet.labels.get(addr,"")), self.wallet.addresses())
        self.print_list(messages, "%19s  %25s "%("Address", "Label"))

    def print_order(self):
        print("send order to " + self.str_recipient + ", amount: " + self.str_amount \
              + "\nfee: " + self.str_fee + ", desc: " + self.str_description)

    def enter_order(self):
        self.str_recipient = raw_input("Pay to: ")
        self.str_description = raw_input("Description : ")
        self.str_amount = raw_input("Amount: ")
        self.str_fee = raw_input("Fee: ")

    def send_order(self):
        self.do_send()

    def print_banner(self):
        for i, x in enumerate( self.wallet.network.banner.split('\n') ):
            print( x )

    def print_list(self, list, firstline):
        self.maxpos = len(list)
        if not self.maxpos: return
        print(firstline)
        for i in range(self.maxpos):
            msg = list[i] if i < len(list) else ""
            print(msg)

           
    def main(self,url):
        while self.done == 0: self.main_command()

    def do_send(self):
        if not is_valid(self.str_recipient):
            print(_('Invalid Litecoin address'))
            return
        try:
            amount = int( Decimal( self.str_amount) * 100000000 )
        except Exception:
            print(_('Invalid Amount'))
            return
        try:
            fee = int( Decimal( self.str_fee) * 100000000 )
        except Exception:
            print(_('Invalid Fee'))
            return

        if self.wallet.use_encryption:
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None

        c = ""
        while c != "y":
            c = raw_input("ok to send (y/n)?")
            if c == "n": return

        try:
            tx = self.wallet.mktx( [(self.str_recipient, amount)], password, fee)
        except Exception as e:
            print(str(e))
            return
            
        if self.str_description: 
            self.wallet.labels[tx.hash()] = self.str_description

        h = self.wallet.send_tx(tx)
        print(_("Please wait..."))
        self.wallet.tx_event.wait()
        status, msg = self.wallet.receive_tx( h, tx )

        if status:
            print(_('Payment sent.'))
            #self.do_clear()
            #self.update_contacts_tab()
        else:
            print(_('Error'))

    def network_dialog(self):
        print("use 'electrum setconfig server/proxy' to change your network settings")
        return True


    def settings_dialog(self):
        print("use 'electrum setconfig' to change your settings")
        return True

    def password_dialog(self):
        return getpass.getpass()
        

#   XXX unused

    def run_receive_tab(self, c):
        #if c == 10:
        #    out = self.run_popup('Address', ["Edit label", "Freeze", "Prioritize"])
        return
            
    def run_contacts_tab(self, c):
        pass
#        if c == 10 and self.wallet.addressbook:
#            out = self.run_popup('Adress', ["Copy", "Pay to", "Edit label", "Delete"]).get('button')
#            address = self.wallet.addressbook[self.pos%len(self.wallet.addressbook)]
#            if out == "Pay to":
#                self.tab = 1
#                self.str_recipient = address 
#                self.pos = 2
#            elif out == "Edit label":
#                s = self.get_string(6 + self.pos, 18)
#                if s:
#                    self.wallet.labels[address] = s
