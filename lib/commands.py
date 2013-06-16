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

known_commands = {}
offline_commands = []
protected_commands = []

def register_command(name, min_args, max_args, is_protected, is_offline, description, syntax = '', options_syntax = ''):
    global known_commands, protected_commands, offline_commands
    known_commands[name] = (min_args, max_args, description, syntax, options_syntax)
    if is_protected:
        protected_commands.append(name)
    if is_offline:
        offline_commands.append(name)


payto_options = ' --fee, -f: set transaction fee\n --fromaddr, -s: send from address -\n --changeaddr, -c: send change to address'
listaddr_options = " -a: show all addresses, including change addresses\n -b: include balance in results\n -l: include labels in results"
restore_options = " accepts a seed or master public key."
config_options = " accounts, addr_history, auto_cycle, column_widths, console-history, contacts,\n fee_per_kb, frozen_addresses, gap_limit, imported_keys, labels,\n master_public_key, num_zeros, prioritized_addresses, proxy, seed,\n seed_version, server, transactions, use_change, use_encryption, winpos-qt"

register_command('contacts',             0, 0, False, True,  'Show your list of contacts')
register_command('create',               0, 0, False, True,  'Create a new wallet')
register_command('createmultisig',       2, 2, False, True,  'similar to bitcoind\'s command')
register_command('createrawtransaction', 2, 2, False, True,  'similar to bitcoind\'s command')
register_command('deseed',               0, 0, False, True,  'Remove seed from wallet, creating a seedless, watching-only wallet.')
register_command('decoderawtransaction', 1, 1, False, True,  'similar to bitcoind\'s command')
register_command('dumpprivkey',          1, 1, True,  True,  'Dumps a specified private key for a given address', 'dumpprivkey <bitcoin address>')
register_command('dumpprivkeys',         0, 0, True,  True,  'dump all private keys')
register_command('freeze',               1, 1, False, True,  'Freeze the funds at one of your wallet\'s addresses', 'freeze <address>')
register_command('getbalance',           0, 1, False, False, 'Return the balance of your wallet, or of one account in your wallet', 'getbalance [<account>]')
register_command('getaddressbalance',    1, 1, False, False, 'Return the balance of an address', 'getbalance <address>')
register_command('getaddresshistory',    1, 1, False, False, 'Return the transaction history of an address', 'getaddresshistory <address>')
register_command('getconfig',            1, 1, False, True,  'Return a configuration variable', 'getconfig <name>', config_options)
register_command('getseed',              0, 0, True,  True,  'Print the generation seed of your wallet.')
register_command('help',                 0, 1, False, True,  'Prints this help')
register_command('history',              0, 0, False, False, 'Returns the transaction history of your wallet')
register_command('importprivkey',        1, 1, True,  True,  'Import a private key', 'importprivkey <privatekey>')
register_command('listaddresses',        3, 3, False, True,  'Returns your list of addresses.', '', listaddr_options)
register_command('listunspent',          0, 0, False, True,  'Returns a list of unspent inputs in your wallet.')
register_command('mktx',                 5, 5, True,  True,  'Create a signed transaction', 'mktx <recipient> <amount> [label]', payto_options)
register_command('payto',                5, 5, True,  False, 'Create and broadcast a transaction.', "payto <recipient> <amount> [label]\n<recipient> can be a bitcoin address or a label", payto_options)
register_command('password',             0, 0, True,  True,  'Change your password')
register_command('prioritize',           1, 1, False, True,  'Coins at prioritized addresses are spent first.', 'prioritize <address>')
register_command('restore',              0, 0, False, False, 'Restore a wallet', '', restore_options)
register_command('setconfig',            2, 2, False, True,  'Set a configuration variable', 'setconfig <name> <value>', config_options)
register_command('setlabel',             2,-1, False, True,  'Assign a label to an item', 'setlabel <tx_hash> <label>')
register_command('sendrawtransaction',   1, 1, False, False, 'Broadcasts a transaction to the network.', 'sendrawtransaction <tx in hexadecimal>')
register_command('signrawtransaction',   1, 3, True,  True,  'similar to bitcoind\'s command')
register_command('signmessage',          2,-1, True,  True,  'Sign a message with a key', 'signmessage <address> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "')
register_command('unfreeze',             1, 1, False, True,  'Unfreeze the funds at one of your wallet\'s address', 'unfreeze <address>')
register_command('unprioritize',         1, 1, False, True,  'Unprioritize an address', 'unprioritize <address>')
register_command('validateaddress',      1, 1, False, True,  'Check that the address is valid', 'validateaddress <address>')
register_command('verifymessage',        3,-1, False, True,  'Verifies a signature', 'verifymessage <address> <signature> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "')
    



class Commands:

    def __init__(self, wallet, interface, callback = None):
        self.wallet = wallet
        self.interface = interface
        self._callback = callback
        self.password = None

    def _run(self, method, args, password_getter):
        if method in protected_commands and self.wallet.use_encryption:
            self.password = apply(password_getter,())
        f = eval('self.'+method)
        result = apply(f,args)
        self.password = None
        if self._callback:
            apply(self._callback, ())
        return result

    def getaddresshistory(self, addr):
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
        r, h = self.wallet.sendtx( tx )
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
            addresses = self.wallet.addresses(True)
        return self.wallet.get_private_keys(addresses, self.password)

    def validateaddress(self,addr):
        isvalid = is_valid(addr)
        out = { 'isvalid':isvalid }
        if isvalid:
            is_mine = self.wallet.is_mine(addr)
            out['address'] = addr
            out['ismine'] = is_mine
            if is_mine:
                out['pubkey'] = self.wallet.get_public_key(addr)
            
        return out

    def getbalance(self, account= None):
        if account is None:
            c, u = self.wallet.get_balance()
        else:
            c, u = self.wallet.get_account_balance(account)

        out = { "confirmed": str(Decimal(c)/100000000) }
        if u: out["unconfirmed"] = str(Decimal(u)/100000000)
        return out

    def getaddressbalance(self, addr):
        c, u = self.wallet.get_addr_balance(addr)
        out = { "confirmed": str(Decimal(c)/100000000) }
        if u: out["unconfirmed"] = str(Decimal(u)/100000000)
        return out


    def getseed(self):
        import mnemonic
        seed = self.wallet.decode_seed(self.password)
        return { "hex":seed, "mnemonic": ' '.join(mnemonic.mn_encode(seed)) }

    def importprivkey(self, sec):
        try:
            addr = self.wallet.import_key(sec,self.password)
            self.wallet.save()
            out = "Keypair imported: ", addr
        except BaseException as e:
            out = "Error: Keypair import failed: " + str(e)
        return out


    def signmessage(self, address, message):
        return self.wallet.sign_message(address, message, self.password)


    def verifymessage(self, address, signature, message):
        return self.wallet.verify_message(address, signature, message)


    def _mktx(self, to_address, amount, fee = None, change_addr = None, domain = None):

        if not is_valid(to_address):
            raise BaseException("Invalid Bitcoin address", to_address)

        if change_addr:
            if not is_valid(change_addr):
                raise BaseException("Invalid Bitcoin address", change_addr)

        if domain is not None:
            for addr in domain:
                if not is_valid(addr):
                    raise BaseException("invalid Bitcoin address", addr)
            
                if not self.wallet.is_mine(addr):
                    raise BaseException("address not in wallet", addr)

        for k, v in self.wallet.labels.items():
            if v == to_address:
                to_address = k
                print_msg("alias", to_address)
                break
            if change_addr and v == change_addr:
                change_addr = k

        amount = int(100000000*amount)
        if fee: fee = int(100000000*fee)
        return self.wallet.mktx( [(to_address, amount)], self.password, fee , change_addr, domain)


    def mktx(self, to_address, amount, fee = None, change_addr = None, domain = None):
        tx = self._mktx(to_address, amount, fee, change_addr, domain)
        return tx.as_dict()


    def payto(self, to_address, amount, fee = None, change_addr = None, domain = None):
        tx = self._mktx(to_address, amount, fee, change_addr, domain)
        r, h = self.wallet.sendtx( tx )
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


    def listaddresses(self, show_all = False, show_balance = False, show_label = False):
        out = []
        for addr in self.wallet.addresses(True):
            if show_all or not self.wallet.is_change(addr):
                if show_balance or show_label:
                    item = { 'address': addr }
                    if show_balance:
                        item['balance'] = str(Decimal(self.wallet.get_addr_balance(addr)[0])/100000000)
                    if show_label:
                        label = self.wallet.labels.get(addr,'')
                        if label:
                            item['label'] = label
                else:
                    item = addr
                out.append( item )
        return out
                         
    def help(self, cmd2=None):
        if cmd2 not in known_commands:
            print_msg("\nList of commands:", ', '.join(sorted(known_commands)))
        else:
            _, _, description, syntax, options_syntax = known_commands[cmd2]
            print_msg(description)
            if syntax: print_msg("Syntax: " + syntax)
            if options_syntax: print_msg("options:\n" + options_syntax)
        return None


