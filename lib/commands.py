#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


from util import *
from bitcoin import *
from decimal import Decimal
import bitcoin

known_commands = {
    'help':'Prints this help',
    'validateaddress':'Check that the address is valid', 
    'balance': "Display the balance of your wallet or of an address.\nSyntax: balance [<address>]", 
    'contacts': "Show your list of contacts", 
    'create':'Create a wallet', 
    'restore':'Restore a wallet', 
    'payto':"""Create and broadcast a transaction.
Syntax: payto <recipient> <amount> [label]
<recipient> can be a bitcoin address or a label
options:\n  --fee, -f: set transaction fee\n  --fromaddr, -s: send from address -\n  --changeaddr, -c: send change to address
            """,
    'sendrawtransaction':
            'Broadcasts a transaction to the network. \nSyntax: sendrawtransaction <tx in hexadecimal>',
    'password': 
            "Changes your password",
    'addresses':  
            """Shows your list of addresses.
options:
  -a: show all addresses, including change addresses""",

    'history':"Shows the transaction history",
    'setlabel':'Assign a label to an item\nSyntax: label <tx_hash> <label>',
    'mktx':
        """Create a signed transaction, password protected.
Syntax: mktx <recipient> <amount> [label]
options:\n  --fee, -f: set transaction fee\n  --fromaddr, -s: send from address -\n  --changeaddr, -c: send change to address
        """,
    'get_seed':
            "Print the generation seed of your wallet.",
    'importprivkey': 
            'Import a private key\nSyntax: importprivkey <privatekey>',
    'signmessage':
            'Signs a message with a key\nSyntax: signmessage <address> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "',
    'verifymessage':
             'Verifies a signature\nSyntax: verifymessage <address> <signature> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "',
    'eval':  
             "Run python eval() on an object\nSyntax: eval <expression>\nExample: eval \"wallet.aliases\"",
    'get': 
             "Get config parameter.",
    'set': 
             "Set config parameter.",
    'deseed':
            "Create a seedless, watching-only wallet.",
    'freeze':'',
    'unfreeze':'',
    'prioritize':'',
    'unprioritize':'',
    'dumpprivkey':'similar to bitcoind\'s command',
    'dumpprivkeys':'dump all private keys',
    'listunspent':'similar to bitcoind\'s command',
    'createmultisig':'similar to bitcoind\'s command',
    'createrawtransaction':'similar to bitcoind\'s command',
    'decoderawtransaction':'similar to bitcoind\'s command',
    'signrawtransaction':'similar to bitcoind\'s command',
    'get_history': 'get history for an address'
    
    }



offline_commands = [ 'password', 'mktx',
                     'setlabel', 'contacts',
                     'help', 'validateaddress',
                     'signmessage', 'verifymessage',
                     'eval', 'set', 'get', 'create', 'addresses',
                     'importprivkey', 'get_seed',
                     'deseed',
                     'freeze','unfreeze',
                     'prioritize','unprioritize',
                     'dumpprivkey','dumpprivkeys','listunspent',
                     'createmultisig', 'createrawtransaction', 'decoderawtransaction', 'signrawtransaction'
                     ]

protected_commands = ['payto', 'password', 'mktx', 'get_seed', 'importprivkey','signmessage', 'signrawtransaction', 'dumpprivkey', 'dumpprivkeys' ]

class Commands:

    def __init__(self, wallet, interface, callback = None):
        self.wallet = wallet
        self.interface = interface
        self._callback = callback

    def _run(self, method, args, password_getter):
        if method in protected_commands:
            self.password = apply(password_getter,())
        f = eval('self.'+method)
        result = apply(f,args)
        self.password = None
        if self._callback:
            apply(self._callback, ())
        return result

    def get_history(self, addr):
        h = self.wallet.get_history(addr)
        if h is None: h = self.wallet.interface.synchronous_get([ ('blockchain.address.get_history',[addr]) ])[0]
        return h

    def listunspent(self):
        import copy
        l = copy.deepcopy(self.wallet.get_unspent_coins())
        for i in l: i["value"] = str(Decimal(i["value"])/100000000)
        return l

    def createrawtransaction(self, inputs, outputs):
        # convert to own format
        for i in inputs:
            i['tx_hash'] = i['txid']
            i['index'] = i['vout']
        outputs = map(lambda x: (x[0],int(1e8*x[1])), outputs.items())
        tx = Transaction.from_io(inputs, outputs)
        return tx.as_dict()

    def signrawtransaction(self, raw_tx, input_info, private_keys):
        tx = Transaction(raw_tx)
        self.wallet.signrawtransaction(tx, input_info, private_keys, self.password)
        return tx.as_dict()

    def decoderawtransaction(self, raw):
        tx = Transaction(raw)
        return tx.deserialize()

    def sendrawtransaction(self, raw):
        tx = Transaction(raw)
        r, h = wallet.sendtx( tx )
        return h

    def createmultisig(self, num, pubkeys):
        assert isinstance(pubkeys, list)
        return Transaction.multisig_script(pubkeys, num)
    
    def freeze(self,addr):
        return self.wallet.freeze(addr)
        
    def unfreeze(self,addr):
        return self.wallet.unfreeze(addr)

    def prioritize(self, addr):
        return self.wallet.prioritize(addr)

    def unprioritize(self, addr):
        return self.wallet.unprioritize(addr)

    def dumpprivkey(self, addr):
        return self.wallet.get_private_key(addr, self.password)

    def dumpprivkeys(self, addresses = None):
        if addresses is None:
            addresses = self.wallet.all_addresses()
        return self.wallet.get_private_keys(addresses, self.password)

    def validateaddress(self,addr):
        is_valid = self.wallet.is_valid(addr)
        out = { 'isvalid':is_valid }
        if is_valid:
            is_mine = self.wallet.is_mine(addr)
            out['address'] = addr
            out['ismine'] = is_mine
            if is_mine:
                out['pubkey'] = self.wallet.get_public_key(addr)
            
        return out

        
    def balance(self, addresses = []):
        if addresses == []:
            c, u = self.wallet.get_balance()
        else:
            c = u = 0
            for addr in addresses:
                cc, uu = wallet.get_addr_balance(addr)
                c += cc
                u += uu

        out = { "confirmed": str(Decimal(c)/100000000) }
        if u: out["unconfirmed"] = str(Decimal(u)/100000000)
        return out


    def get_seed(self):
        import mnemonic
        seed = self.wallet.decode_seed(self.password)
        return { "hex":seed, "mnemonic": ' '.join(mnemonic.mn_encode(seed)) }

    def importprivkey(self, sec):
        try:
            addr = wallet.import_key(sec,self.password)
            wallet.save()
            out = "Keypair imported: ", addr
        except BaseException as e:
            out = "Error: Keypair import failed: " + str(e)
        return out


    def sign_message(self, address, message):
        return self.wallet.sign_message(address, message, self.password)


    def verify_message(self, address, signature, message):
        try:
            EC_KEY.verify_message(address, signature, message)
            return True
        except BaseException as e:
            print_error("Verification error: {0}".format(e))
            return False


    def _mktx(self, to_address, amount, fee = None, change_addr = None, from_addr = None):
        for k, v in self.wallet.labels.items():
            if v == to_address:
                to_address = k
                print_msg("alias", to_address)
                break
            if change_addr and v == change_addr:
                change_addr = k

        amount = int(10000000*amount)
        if fee: fee = int(10000000*fee)
        return self.wallet.mktx( [(to_address, amount)], self.password, fee , change_addr, from_addr)


    def mktx(self, to_address, amount, fee = None, change_addr = None, from_addr = None):
        tx = self._mktx(to_address, amount, fee, change_addr, from_addr)
        return tx.as_dict()


    def payto(self, to_address, amount, fee = None, change_addr = None, from_addr = None):
        tx = self._mktx(to_address, amount, fee, change_addr, from_addr)
        r, h = wallet.sendtx( tx )
        return h


    def history(self):
        import datetime
        balance = 0
        out = []
        for item in self.wallet.get_tx_history():
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            try:
                time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
            except:
                time_str = "----"

            label, is_default_label = self.wallet.get_label(tx_hash)
            if not label: label = tx_hash
            else: label = label + ' '*(64 - len(label) )

            out.append( "%16s"%time_str + "  " + label + "  " + format_satoshis(value)+ "  "+ format_satoshis(balance) )
        return out



    def setlabel(self, tx, label):
        self.wallet.labels[tx] = label
        self.wallet.save()
            

    def contacts(self):
        c = {}
        for addr in self.wallet.addressbook:
            c[addr] = self.wallet.labels.get(addr)
        return c


    def addresses(self, show_all):
        out = []
        for addr in self.wallet.all_addresses():
            if show_all or not self.wallet.is_change(addr):

                flags = self.wallet.get_address_flags(addr)
                label = self.wallet.labels.get(addr,'')
                if label: label = "\"%s\""%label
                b = format_satoshis(self.wallet.get_addr_balance(addr)[0])
                m_addr = "%34s"%addr
                out.append( flags + ' ' + m_addr + ' ' + b + ' ' + label )
        return out
                         

