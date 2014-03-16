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

import time
from util import *
from bitcoin import *
from decimal import Decimal
import bitcoin
from transaction import Transaction

class Command:
    def __init__(self, name, min_args, max_args, requires_network, requires_wallet, requires_password, description, syntax = '', options_syntax = ''):
        self.name = name
        self.min_args=min_args
        self.max_args = max_args
        self.requires_network = requires_network
        self.requires_wallet = requires_wallet
        self.requires_password = requires_password
        self.description = description
        self.syntax = syntax
        self.options = options_syntax

known_commands = {}
def register_command(*args):
    global known_commands
    name = args[0]
    known_commands[name] = Command(*args)



payto_options = ' --fee, -f: set transaction fee\n --fromaddr, -F: send from address -\n --changeaddr, -c: send change to address'
listaddr_options = " -a: show all addresses, including change addresses\n -l: include labels in results"
restore_options = " accepts a seed or master public key."
mksendmany_syntax = 'mksendmanytx <recipient> <amount> [<recipient> <amount> ...]'
payto_syntax = "payto <recipient> <amount> [label]\n<recipient> can be a bitcoin address or a label"
paytomany_syntax = "paytomany <recipient> <amount> [<recipient> <amount> ...]\n<recipient> can be a bitcoin address or a label"
signmessage_syntax = 'signmessage <address> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "'
verifymessage_syntax = 'verifymessage <address> <signature> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "'


#                command
#                                              requires_network
#                                                     requires_wallet
#                                                            requires_password
register_command('contacts',             0, 0, False, True,  False, 'Show your list of contacts')
register_command('create',               0, 0, False, True,  False, 'Create a new wallet')
register_command('createmultisig',       2, 2, False, True,  False, 'similar to bitcoind\'s command')
register_command('createrawtransaction', 2, 2, False, True,  False, 'similar to bitcoind\'s command')
register_command('deseed',               0, 0, False, True,  False, 'Remove seed from wallet, creating a seedless, watching-only wallet.')
register_command('decoderawtransaction', 1, 1, False, False, False, 'similar to bitcoind\'s command')
register_command('dumpprivkey',          1, 1, False, True,  True,  'Dumps a specified private key for a given address', 'dumpprivkey <bitcoin address>')
register_command('dumpprivkeys',         0, 0, False, True,  True,  'dump all private keys')
register_command('freeze',               1, 1, False, True,  True,  'Freeze the funds at one of your wallet\'s addresses', 'freeze <address>')
register_command('getbalance',           0, 1, True,  True,  False, 'Return the balance of your wallet, or of one account in your wallet', 'getbalance [<account>]')
register_command('getservers',           0, 0, True,  False, False, 'Return the list of available servers')
register_command('getversion',           0, 0, False, False, False, 'Return the version of your client', 'getversion')
register_command('getaddressbalance',    1, 1, True,  False, False, 'Return the balance of an address', 'getaddressbalance <address>')
register_command('getaddresshistory',    1, 1, True,  False, False, 'Return the transaction history of a wallet address', 'getaddresshistory <address>')
register_command('getconfig',            1, 1, False, False, False, 'Return a configuration variable', 'getconfig <name>')
register_command('getpubkeys',           1, 1, False, True,  False, 'Return the public keys for a wallet address', 'getpubkeys <bitcoin address>')
register_command('getrawtransaction',    1, 1, True,  False, False, 'Retrieve a transaction', 'getrawtransaction <txhash>')
register_command('getseed',              0, 0, False, True,  True,  'Print the generation seed of your wallet.')
register_command('getmpk',               0, 0, False, True,  False, 'Return your wallet\'s master public key', 'getmpk')
register_command('help',                 0, 1, False, False, False, 'Prints this help')
register_command('history',              0, 0, True,  True,  False, 'Returns the transaction history of your wallet')
register_command('importprivkey',        1, 1, False, True,  True,  'Import a private key', 'importprivkey <privatekey>')
register_command('listaddresses',        2, 2, False, True,  False, 'Returns your list of addresses.', '', listaddr_options)
register_command('listunspent',          0, 0, True,  True,  False, 'Returns the list of unspent inputs in your wallet.')
register_command('getaddressunspent',    1, 1, True,  False, False, 'Returns the list of unspent inputs for an address.')
register_command('mktx',                 5, 5, False, True,  True,  'Create a signed transaction', 'mktx <recipient> <amount> [label]', payto_options)
register_command('mksendmanytx',         4, 4, False, True,  True,  'Create a signed transaction', mksendmany_syntax, payto_options)
register_command('payto',                5, 5, True,  True,  True,  'Create and broadcast a transaction.', payto_syntax, payto_options)
register_command('paytomany',            4, 4, True,  True,  True,  'Create and broadcast a transaction.', paytomany_syntax, payto_options)
register_command('password',             0, 0, False, True,  True,  'Change your password')
register_command('restore',              0, 0, True,  True,  False, 'Restore a wallet', '', restore_options)
register_command('setconfig',            2, 2, False, False, False, 'Set a configuration variable', 'setconfig <name> <value>')
register_command('setlabel',             2,-1, False, True,  False, 'Assign a label to an item', 'setlabel <tx_hash> <label>')
register_command('sendrawtransaction',   1, 1, True,  False, False, 'Broadcasts a transaction to the network.', 'sendrawtransaction <tx in hexadecimal>')
register_command('signrawtransaction',   1, 3, False, True,  True,  'similar to bitcoind\'s command')
register_command('signmessage',          2,-1, False, True,  True,  'Sign a message with a key', signmessage_syntax)
register_command('unfreeze',             1, 1, False, True,  False, 'Unfreeze the funds at one of your wallet\'s address', 'unfreeze <address>')
register_command('validateaddress',      1, 1, False, False, False, 'Check that the address is valid', 'validateaddress <address>')
register_command('verifymessage',        3,-1, False, False, False, 'Verifies a signature', verifymessage_syntax)

#register_command('encrypt',              2,-1, False, False, False, 'encrypt a message with pubkey','encrypt <pubkey> <message>')
#register_command('decrypt',              2,-1, False, True, True,   'decrypt a message encrypted with pubkey','decrypt <pubkey> <message>')
register_command('daemon',               1, 1, True, False, False,  '<stop|status>')
register_command('getproof',             1, 1, True, False, False, 'get merkle proof', 'getproof <address>')
register_command('getutxoaddress',       2, 2, True, False, False, 'get the address of an unspent transaction output','getutxoaddress <txid> <pos>')




class Commands:

    def __init__(self, wallet, network, callback = None):
        self.wallet = wallet
        self.network = network
        self._callback = callback
        self.password = None


    def _run(self, method, args, password_getter):
        cmd = known_commands[method]
        if cmd.requires_password and self.wallet.use_encryption:
            self.password = apply(password_getter,())
        f = getattr(self, method)
        result = f(*args)
        self.password = None
        if self._callback:
            apply(self._callback, ())
        return result


    def getaddresshistory(self, addr):
        return self.network.synchronous_get([ ('blockchain.address.get_history',[addr]) ])[0]


    def daemon(self, arg):
        if arg=='stop':
            return self.network.stop()
        elif arg=='status':
            return { 
                'server':self.network.main_server(), 
                'connected':self.network.is_connected()
            }
        else:
            return "unknown command \"%s\""% arg


    def listunspent(self):
        import copy
        l = copy.deepcopy(self.wallet.get_unspent_coins())
        for i in l: i["value"] = str(Decimal(i["value"])/100000000)
        return l


    def getaddressunspent(self, addr):
        return self.network.synchronous_get([ ('blockchain.address.listunspent',[addr]) ])[0]


    def getutxoaddress(self, txid, num):
        r = self.network.synchronous_get([ ('blockchain.utxo.get_address',[txid, num]) ])
        if r: 
            return {'address':r[0] }


    def createrawtransaction(self, inputs, outputs):
        inputs = map(lambda i: {'prevout_hash': i['txid'], 'prevout_n':i['vout']}, inputs )
        outputs = map(lambda x: (x[0],int(1e8*x[1])), outputs.items())
        tx = Transaction.from_io(inputs, outputs)
        return tx


    def signrawtransaction(self, raw_tx, input_info, private_keys):
        tx = Transaction(raw_tx)
        self.wallet.signrawtransaction(tx, input_info, private_keys, self.password)
        return tx

    def decoderawtransaction(self, raw):
        tx = Transaction(raw)
        return tx.deserialize()

    def sendrawtransaction(self, raw):
        tx = Transaction(raw)
        return self.network.synchronous_get([('blockchain.transaction.broadcast', [str(tx)])])[0]

    def createmultisig(self, num, pubkeys):
        assert isinstance(pubkeys, list)
        redeem_script = Transaction.multisig_script(pubkeys, num)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return {'address':address, 'redeemScript':redeem_script}
    
    def freeze(self,addr):
        return self.wallet.freeze(addr)
        
    def unfreeze(self,addr):
        return self.wallet.unfreeze(addr)

    def dumpprivkey(self, addr):
        return self.wallet.get_private_key(addr, self.password)

    def dumpprivkeys(self, addresses = None):
        if addresses is None:
            addresses = self.wallet.addresses(True)
        return [self.wallet.get_private_key(address, self.password) for address in addresses]

    def validateaddress(self, addr):
        isvalid = is_valid(addr)
        out = { 'isvalid':isvalid }
        if isvalid:
            out['address'] = addr
        return out

    def getpubkeys(self, addr):
        out = { 'address':addr }
        out['pubkeys'] = self.wallet.getpubkeys(addr)
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
        out = self.network.synchronous_get([ ('blockchain.address.get_balance',[addr]) ])[0]
        out["confirmed"] =  str(Decimal(out["confirmed"])/100000000)
        out["unconfirmed"] =  str(Decimal(out["unconfirmed"])/100000000)
        return out


    def getproof(self, addr):
        p = self.network.synchronous_get([ ('blockchain.address.get_proof',[addr]) ])[0]
        out = []
        for i,s in p:
            out.append(i)
        return out

    def getservers(self):
        while not self.network.is_up_to_date():
            time.sleep(0.1)
        return self.network.get_servers()

    def getversion(self):
        import electrum 
        return electrum.ELECTRUM_VERSION
 
    def getmpk(self):
        return self.wallet.get_master_public_key()

    def getseed(self):
        mnemonic = self.wallet.get_mnemonic(self.password)
        seed = self.wallet.get_seed(self.password)
        return { 'mnemonic':mnemonic, 'seed':seed, 'version':self.wallet.seed_version }

    def importprivkey(self, sec):
        try:
            addr = self.wallet.import_key(sec,self.password)
            out = "Keypair imported: ", addr
        except Exception as e:
            out = "Error: Keypair import failed: " + str(e)
        return out


    def signmessage(self, address, message):
        return self.wallet.sign_message(address, message, self.password)


    def verifymessage(self, address, signature, message):
        return bitcoin.verify_message(address, signature, message)


    def _mktx(self, outputs, fee = None, change_addr = None, domain = None):

        for to_address, amount in outputs:
            if not is_valid(to_address):
                raise Exception("Invalid Bitcoin address", to_address)

        if change_addr:
            if not is_valid(change_addr):
                raise Exception("Invalid Bitcoin address", change_addr)

        if domain is not None:
            for addr in domain:
                if not is_valid(addr):
                    raise Exception("invalid Bitcoin address", addr)
            
                if not self.wallet.is_mine(addr):
                    raise Exception("address not in wallet", addr)

        for k, v in self.wallet.labels.items():
            if change_addr and v == change_addr:
                change_addr = k

        final_outputs = []
        for to_address, amount in outputs:
            for k, v in self.wallet.labels.items():
                if v == to_address:
                    to_address = k
                    print_msg("alias", to_address)
                    break

            amount = int(100000000*amount)
            final_outputs.append((to_address, amount))
            
        if fee: fee = int(100000000*fee)
        return self.wallet.mktx(final_outputs, self.password, fee , change_addr, domain)


    def mktx(self, to_address, amount, fee = None, change_addr = None, domain = None):
        tx = self._mktx([(to_address, amount)], fee, change_addr, domain)
        return tx

    def mksendmanytx(self, outputs, fee = None, change_addr = None, domain = None):
        tx = self._mktx(outputs, fee, change_addr, domain)
        return tx


    def payto(self, to_address, amount, fee = None, change_addr = None, domain = None):
        tx = self._mktx([(to_address, amount)], fee, change_addr, domain)
        r, h = self.wallet.sendtx( tx )
        return h

    def paytomany(self, outputs, fee = None, change_addr = None, domain = None):
        tx = self._mktx(outputs, fee, change_addr, domain)
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
            except Exception:
                time_str = "----"

            label, is_default_label = self.wallet.get_label(tx_hash)

            out.append({'txid':tx_hash, 'date':"%16s"%time_str, 'label':label, 'value':format_satoshis(value)})
        return out



    def setlabel(self, key, label):
        self.wallet.set_label(key, label)

            

    def contacts(self):
        c = {}
        for addr in self.wallet.addressbook:
            c[addr] = self.wallet.labels.get(addr)
        return c


    def listaddresses(self, show_all = False, show_label = False):
        out = []
        for addr in self.wallet.addresses(True):
            if show_all or not self.wallet.is_change(addr):
                if show_label:
                    item = { 'address': addr }
                    if show_label:
                        label = self.wallet.labels.get(addr,'')
                        if label:
                            item['label'] = label
                else:
                    item = addr
                out.append( item )
        return out
                         
    def help(self, cmd=None):
        if cmd not in known_commands:
            print_msg("\nList of commands:", ', '.join(sorted(known_commands)))
        else:
            cmd = known_commands[cmd]
            print_msg(cmd.description)
            if cmd.syntax: print_msg("Syntax: " + cmd.syntax)
            if cmd.options: print_msg("options:\n" + cmd.options)
        return None


    def getrawtransaction(self, tx_hash):
        import transaction
        if self.wallet:
            tx = self.wallet.transactions.get(tx_hash)
            if tx:
                return tx

        r = self.network.synchronous_get([ ('blockchain.transaction.get',[tx_hash]) ])[0]
        if r:
            return transaction.Transaction(r)
        else:
            return "unknown transaction"


    def encrypt(self, pubkey, message):
        return bitcoin.encrypt_message(message, pubkey)


    def decrypt(self, pubkey, message):
        return self.wallet.decrypt_message(pubkey, message, self.password)



