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

import sys
import datetime
import time
import copy
import argparse
import json
import ast

import util
from util import print_msg, format_satoshis, print_stderr
from bitcoin import is_address, hash_160_to_bc_address, hash_160
from decimal import Decimal
import bitcoin
from transaction import Transaction


class Commands:

    def __init__(self, config, wallet, network, callback = None):
        self.config = config
        self.wallet = wallet
        self.network = network
        self._callback = callback
        self.password = None
        self.contacts = util.Contacts(self.config)

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

    def help(self):
        return 'Commands: ' + ', '.join(sorted(known_commands.keys()))

    # dummy functions for register
    def create(self): pass
    def restore(self): pass
    def deseed(self): pass
    def password(self): pass

    def getconfig(self, key):
        return self.config.get(key)

    def setconfig(self, key, value):
        try:
            value = ast.literal_eval(value)
        except:
            pass
        self.config.set_key(key, value, True)
        return True

    def make_seed(self, nbits=128, entropy=1, language=None):
        from mnemonic import Mnemonic
        s = Mnemonic(language).make_seed(nbits, custom_entropy=custom_entropy)
        return s.encode('utf8')

    def check_seed(self, seed, entropy=1, language=None):
        from mnemonic import Mnemonic
        return Mnemonic(language).check_seed(seed, entropy)

    def getaddresshistory(self, address):
        return self.network.synchronous_get([('blockchain.address.get_history', [address])])[0]

    def listunspent(self):
        l = copy.deepcopy(self.wallet.get_spendable_coins(exclude_frozen = False))
        for i in l: i["value"] = str(Decimal(i["value"])/100000000)
        return l

    def getaddressunspent(self, address):
        return self.network.synchronous_get([('blockchain.address.listunspent', [address])])[0]

    def getutxoaddress(self, txid, pos):
        r = self.network.synchronous_get([('blockchain.utxo.get_address', [txid, pos])])
        if r:
            return {'address':r[0]}

    def createrawtx(self, inputs, outputs, unsigned=False):
        coins = self.wallet.get_spendable_coins(exclude_frozen = False)
        tx_inputs = []
        for i in inputs:
            prevout_hash = i['txid']
            prevout_n = i['vout']
            for c in coins:
                if c['prevout_hash'] == prevout_hash and c['prevout_n'] == prevout_n:
                    self.wallet.add_input_info(c)
                    tx_inputs.append(c)
                    break
            else:
                raise BaseException('Transaction output not in wallet', prevout_hash+":%d"%prevout_n)
        outputs = map(lambda x: ('address', x[0], int(1e8*x[1])), outputs.items())
        tx = Transaction.from_io(tx_inputs, outputs)
        if not unsigned:
            self.wallet.sign_transaction(tx, self.password)
        return tx

    def signtransaction(self, tx, privkey=None):
        tx = Transaction(tx)
        tx.deserialize()
        if privkey:
            pubkey = bitcoin.public_key_from_private_key(sec)
            tx.sign({pubkey:sec})
        else:
            self.wallet.sign_transaction(tx, self.password)
        return tx

    def decodetx(self, tx):
        t = Transaction(rawtx)
        return t.deserialize()

    def sendtx(self, tx):
        t = Transaction(raw)
        return self.network.synchronous_get([('blockchain.transaction.broadcast', [str(t)])])[0]

    def createmultisig(self, num, pubkeys):
        assert isinstance(pubkeys, list), (type(num), type(pubkeys))
        redeem_script = Transaction.multisig_script(pubkeys, num)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return {'address':address, 'redeemScript':redeem_script}

    def freeze(self, address):
        return self.wallet.set_frozen_state([address], True)

    def unfreeze(self, address):
        return self.wallet.set_frozen_state([address], False)

    def getprivatekeys(self, address):
        return self.wallet.get_private_key(address, self.password)

    def ismine(self, address):
        return self.wallet.is_mine(address)

    def dumpprivkeys(self, domain=None):
        if domain is None:
            domain = self.wallet.addresses(True)
        return [self.wallet.get_private_key(address, self.password) for address in domain]

    def validateaddress(self, address):
        return is_address(address)

    def getpubkeys(self, address):
        return self.wallet.get_public_keys(address)

    def getbalance(self, account=None):
        if account is None:
            c, u, x = self.wallet.get_balance()
        else:
            c, u, x = self.wallet.get_account_balance(account)
        out = {"confirmed": str(Decimal(c)/100000000)}
        if u:
            out["unconfirmed"] = str(Decimal(u)/100000000)
        if x:
            out["unmatured"] = str(Decimal(x)/100000000)
        return out

    def getaddressbalance(self, address):
        out = self.network.synchronous_get([('blockchain.address.get_balance', [address])])[0]
        out["confirmed"] =  str(Decimal(out["confirmed"])/100000000)
        out["unconfirmed"] =  str(Decimal(out["unconfirmed"])/100000000)
        return out

    def getproof(self, address):
        p = self.network.synchronous_get([('blockchain.address.get_proof', [address])])[0]
        out = []
        for i,s in p:
            out.append(i)
        return out

    def getmerkle(self, txid, height):
        return self.network.synchronous_get([('blockchain.transaction.get_merkle', [txid, int(height)])])[0]

    def getservers(self):
        while not self.network.is_up_to_date():
            time.sleep(0.1)
        return self.network.get_servers()

    def version(self):
        import electrum_ltc as electrum  # Needs to stay here to prevent ciruclar imports
        return electrum.ELECTRUM_VERSION

    def getmpk(self):
        return self.wallet.get_master_public_keys()

    def getseed(self):
        s = self.wallet.get_mnemonic(self.password)
        return s.encode('utf8')

    def importprivkey(self, privkey):
        try:
            addr = self.wallet.import_key(privkey, self.password)
            out = "Keypair imported: ", addr
        except Exception as e:
            out = "Error: Keypair import failed: " + str(e)
        return out

    def sweep(self, privkey, destination, tx_fee=None, nocheck=False):
        resolver = lambda x: self.contacts.resolve(x, nocheck)['address']
        dest = resolver(destination)
        if tx_fee is None:
            tx_fee = 0.001
        fee = int(Decimal(tx_fee)*100000000)
        return Transaction.sweep([privkey], self.network, dest, fee)

    def signmessage(self, address, message):
        return self.wallet.sign_message(address, message, self.password)

    def verifymessage(self, address, signature, message):
        return bitcoin.verify_message(address, signature, message)

    def _mktx(self, outputs, fee, change_addr, domain, nocheck, unsigned, deserialized):
        resolver = lambda x: None if x is None else self.contacts.resolve(x, nocheck)['address']
        change_addr = resolver(change_addr)
        domain = None if domain is None else map(resolver, domain)
        fee = None if fee is None else int(100000000*Decimal(fee))
        final_outputs = []
        for address, amount in outputs:
            address = resolver(address)
            #assert self.wallet.is_mine(address)
            if amount == '!':
                assert len(outputs) == 1
                inputs = self.wallet.get_spendable_coins(domain)
                amount = sum(map(lambda x:x['value'], inputs))
                if fee is None:
                    for i in inputs:
                        self.wallet.add_input_info(i)
                    output = ('address', address, amount)
                    dummy_tx = Transaction.from_io(inputs, [output])
                    fee = self.wallet.estimated_fee(dummy_tx)
                amount -= fee
            else:
                amount = int(100000000*Decimal(amount))
            final_outputs.append(('address', address, amount))

        coins = self.wallet.get_spendable_coins(domain)
        tx = self.wallet.make_unsigned_transaction(coins, final_outputs, fee, change_addr)
        str(tx) #this serializes
        if not unsigned:
            self.wallet.sign_transaction(tx, self.password)
        return tx.deserialize() if deserialized else tx

    def _read_csv(self, csvpath):
        import csv
        outputs = []
        with open(csvpath, 'rb') as csvfile:
            csvReader = csv.reader(csvfile, delimiter=',')
            for row in csvReader:
                address, amount = row
                assert bitcoin.is_address(address)
                amount = Decimal(amount)
                outputs.append((address, amount))
        return outputs

    def mktx(self, destination, amount, tx_fee=None, from_addr=None, change_addr=None, nocheck=False, unsigned=False, deserialized=False):
        domain = [from_addr] if from_addr else None
        tx = self._mktx([(destination, amount)], tx_fee, change_addr, domain, nocheck, unsigned, deserialized)
        return tx

    def mktx_csv(self, csv_file, tx_fee=None, from_addr=None, change_addr=None, nocheck=False, unsigned=False, deserialized=False):
        domain = [from_addr] if from_addr else None
        outputs = self._read_csv(csv_file)
        tx = self._mktx(outputs, tx_fee, change_addr, domain, nocheck, unsigned, deserialized)
        return tx

    def payto(self, destination, amount, tx_fee=None, from_addr=None, change_addr=None, nocheck=False):
        domain = [from_addr] if from_addr else None
        tx = self._mktx([(destination, amount)], tx_fee, change_addr, domain, nocheck)
        r, h = self.wallet.sendtx(tx)
        return h

    def payto_csv(self, csv_file, tx_fee=None, from_addr=None, change_addr=None, nocheck=False):
        domain = [from_addr] if from_addr else None
        outputs = self._read_csv(csv_file)
        tx = self._mktx(outputs, tx_fee, change_addr, domain, nocheck)
        r, h = self.wallet.sendtx(tx)
        return h

    def history(self):
        balance = 0
        out = []
        for item in self.wallet.get_history():
            tx_hash, conf, value, timestamp, balance = item
            try:
                time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
            except Exception:
                time_str = "----"

            label, is_default_label = self.wallet.get_label(tx_hash)

            out.append({'txid':tx_hash, 'date':"%16s"%time_str, 'label':label, 'value':format_satoshis(value), 'confirmations':conf})
        return out

    def setlabel(self, key, label):
        self.wallet.set_label(key, label)

    def listcontacts(self):
        return self.contacts

    def getalias(self, key, nocheck=False):
        return self.contacts.resolve(key, nocheck)

    def searchcontacts(self, query):
        results = {}
        for key, value in self.contacts.items():
            if query.lower() in key.lower():
                results[key] = value
        return results

    def listaddresses(self, show_all=False, show_labels=False, frozen=False, unused=False, funded=False, show_balance=False):
        out = []
        for addr in self.wallet.addresses(True):
            if frozen and not self.wallet.is_frozen(addr):
                continue
            if not show_all and self.wallet.is_change(addr):
                continue
            if unused and self.wallet.is_used(addr):
                continue
            if funded and self.wallet.is_empty(addr):
                continue
            item = addr
            if show_balance:
                item += ", "+ format_satoshis(sum(self.wallet.get_addr_balance(addr)))
            if show_labels:
                item += ', ' + self.wallet.labels.get(addr,'')
            out.append(item)
        return out

    def gettransaction(self, txid, deserialized=False):
        tx = self.wallet.transactions.get(txid) if self.wallet else None
        if tx is None and self.network:
            raw = self.network.synchronous_get([('blockchain.transaction.get', [txid])])[0]
            if raw:
                tx = Transaction(raw)
            else:
                raise BaseException("Unknown transaction")
        return tx.deserialize() if deserialized else tx

    def encrypt(self, pubkey, message):
        return bitcoin.encrypt_message(message, pubkey)

    def decrypt(self, pubkey, encrypted):
        return self.wallet.decrypt_message(pubkey, encrypted, self.password)



class Command:
    def __init__(self, name, requires_network, requires_wallet, requires_password, help, description):
        self.name = name
        self.requires_network = bool(requires_network)
        self.requires_wallet = bool(requires_wallet)
        self.requires_password = bool(requires_password)
        self.help = help
        self.description = description
        # compute params and options
        func = getattr(Commands, name)
        varnames = func.func_code.co_varnames[1:func.func_code.co_argcount]
        defaults = func.func_defaults
        if defaults:
            n = len(defaults)
            self.params, self.options = list(varnames[:-n]), list(varnames[-n:])
        else:
            self.params, self.options = list(varnames), []



known_commands = {}

def register_command(*args):
    global known_commands
    name = args[0]
    known_commands[name] = Command(*args)


#                command
#                                      requires_network
#                                        requires_wallet
#                                          requires_password
#                                               arguments
#                                                    options
register_command('listcontacts',       0, 0, 0, 'Show your list of contacts', '')
register_command('create',             0, 1, 0, 'Create a new wallet', '')
register_command('createmultisig',     0, 1, 0, 'Create multisig address', '')
register_command('createrawtx',        0, 1, 1, 'Create a transaction from json inputs', 'The syntax is similar to litecoind.')
register_command('deseed',             0, 1, 0, 'Remove seed from wallet.', 'This creates a seedless, watching-only wallet.')
register_command('decodetx',           0, 0, 0, 'Decode serialized transaction', '')
register_command('getprivatekeys',     0, 1, 1, 'Get the private keys of an address', 'Address must be in wallet.')
register_command('dumpprivkeys',       0, 1, 1, 'Dump private keys from your wallet', '')
register_command('freeze',             0, 1, 0, 'Freeze address', 'Freeze the funds at one of your wallet\'s addresses')
register_command('getalias',           0, 0, 0, 'Retrieve alias', 'Lookup in your list of contacts, and for an OpenAlias DNS record')
register_command('getbalance',         1, 1, 0, 'Return the balance of your wallet', '')
register_command('getservers',         1, 0, 0, 'Return the list of available servers', '')
register_command('getaddressbalance',  1, 0, 0, 'Return the balance of an address', '')
register_command('getaddresshistory',  1, 0, 0, 'Return the transaction history of a wallet address', '')
register_command('getconfig',          0, 0, 0, 'Return a configuration variable', '')
register_command('getpubkeys',         0, 1, 0, 'Return the public keys for a wallet address', '')
register_command('gettransaction',     1, 0, 0, 'Retrieve a transaction', '')
register_command('getseed',            0, 1, 1, 'Get seed phrase', 'Print the generation seed of your wallet.')
register_command('getmpk',             0, 1, 0, 'Get Master Public Key', 'Return your wallet\'s master public key')
register_command('help',               0, 0, 0, 'Print help on a command', '')
register_command('history',            1, 1, 0, 'Wallet history', 'Returns the transaction history of your wallet')
register_command('importprivkey',      0, 1, 1, 'Import a private key', '')
register_command('ismine',             0, 1, 0, 'Check if address is in wallet', 'Return true if and only address is in wallet')
register_command('listaddresses',      0, 1, 0, 'List wallet addresses', 'Returns your list of addresses.')
register_command('listunspent',        1, 1, 0, 'List unspent outputs', 'Returns the list of unspent transaction outputs in your wallet.')
register_command('getaddressunspent',  1, 0, 0, 'Returns the list of unspent inputs for an address', '')
register_command('mktx',               0, 1, 1, 'Create a transaction', '')
register_command('payto',              1, 1, 1, 'Create and broadcast a transaction.', '')
register_command('mktx_csv',           0, 1, 1, 'Create a multi-output transaction', '')
register_command('payto_csv',          1, 1, 1, 'Create and broadcast multi-output transaction.', '')
register_command('password',           0, 1, 1, 'Change your password', '')
register_command('restore',            1, 1, 0, 'Restore a wallet from seed', '')
register_command('searchcontacts',     0, 1, 0, 'Search through contacts, return matching entries', '')
register_command('setconfig',          0, 0, 0, 'Set a configuration variable', '')
register_command('setlabel',           0, 1, 0, 'Assign a label to an item', 'Item may be a litecoin address or a transaction ID')
register_command('sendtx',             1, 0, 0, 'Broadcast a transaction to the network', '')
register_command('signtransaction',    0, 1, 1, 'Sign a transaction', 'The wallet keys will be used unless a private key is provided.')
register_command('signmessage',        0, 1, 1, 'Sign a message with a key', 'Use quotes if your message contains whitespaces')
register_command('unfreeze',           0, 1, 0, 'Unfreeze address', 'Unfreeze the funds at one of your wallet\'s address')
register_command('validateaddress',    0, 0, 0, 'Check that the address is valid', '')
register_command('verifymessage',      0, 0, 0, 'Verify a signature', '')
register_command('version',            0, 0, 0, 'Return the version of your client', '')
register_command('encrypt',            0, 0, 0, 'Encrypt a message with a public key', 'Use quotes if the message contains whitespaces.')
register_command('decrypt',            0, 1, 1, 'Decrypt a message encrypted with a public key', '')
register_command('getmerkle',          1, 0, 0, 'Get Merkle branch of a transaction included in a block', '')
register_command('getproof',           1, 0, 0, 'Get Merkle branch of an address in the UTXO set', '')
register_command('getutxoaddress',     1, 0, 0, 'Get the address of an unspent transaction output', '')
register_command('sweep',              1, 0, 0, 'Sweep private key',
                 'Returns a transaction that spends UTXOs from privkey to a destination address. The transaction is not broadcasted.')
register_command('make_seed',          0, 0, 0, 'Create a seed', '')
register_command('check_seed',         0, 0, 0, 'Check that a seed was generated with given entropy', '')

param_descriptions = {
    'privkey': 'Private key. Type \'?\' to get a prompt.',
    'destination': 'Litecoin address, contact or alias',
    'address': 'Litecoin address',
    'seed': 'Seed phrase',
    'txid': 'Transaction ID',
    'pos': 'Position',
    'heigh': 'Block height',
    'tx': 'Serialized transaction (hexadecimal)',
    'key': 'Variable name',
    'pubkey': 'Public key',
    'message': 'Clear text message. Use quotes if it contains spaces.',
    'encrypted': 'Encrypted message',
    'amount': 'Amount to be sent (in LTC). Type \'!\' to send the maximum available.',
    'csv_file': 'CSV file of recipient, amount',
}

command_options = {
    'password':    ("-W", "--password",    None,  "Password"),
    'concealed':   ("-C", "--concealed",   False, "Don't echo seed to console when restoring"),
    'show_all':    ("-a", "--all",         False, "Include change addresses"),
    'frozen':      (None, "--frozen",      False, "Show only frozen addresses"),
    'unused':      (None, "--unused",      False, "Show only unused addresses"),
    'funded':      (None, "--funded",      False, "Show only funded addresses"),
    'show_balance':("-b", "--balance",     False, "Show the balances of listed addresses"),
    'show_labels': ("-l", "--labels",      False, "Show the labels of listed addresses"),
    'nocheck':     (None, "--nocheck",     False, "Do not verify aliases"),
    'tx_fee':      ("-f", "--fee",         None,  "Transaction fee (in LTC)"),
    'from_addr':   ("-F", "--from",        None,  "Source address. If it isn't in the wallet, it will ask for the private key unless supplied in the format public_key:private_key. It's not saved in the wallet."),
    'change_addr': ("-c", "--change",      None,  "Change address. Default is a spare address, or the source address if it's not in the wallet"),
    'nbits':       (None, "--nbits",       128,   "Number of bits of entropy"),
    'entropy':     (None, "--entropy",     1,     "Custom entropy"),
    'language':    ("-L", "--lang",        None,  "Default language for wordlist"),
    'gap_limit':   ("-G", "--gap",         None,  "Gap limit"),
    'mpk':         (None, "--mpk",         None,  "Restore from master public key"),
    'deserialized':("-d", "--deserialized",False, "Return deserialized transaction"),
    'privkey':     (None, "--privkey",     None,  "Private key. Set to '?' to get a prompt."),
    'unsigned':    ("-u", "--unsigned",    False, "Do not sign transaction"),
    'domain':      ("-D", "--domain",      None,  "List of addresses"),
    'account':     (None, "--account",     None,  "Account"),
}


arg_types = {
    'num':int,
    'nbits':int,
    'entropy':long,
    'pubkeys': json.loads,
    'inputs': json.loads,
    'outputs': json.loads,
    'tx_fee': lambda x: Decimal(x) if x is not None else None,
    'amount': lambda x: Decimal(x) if x!='!' else '!',
}


def set_default_subparser(self, name, args=None):
    """see http://stackoverflow.com/questions/5176691/argparse-how-to-specify-a-default-subcommand"""
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help']:  # global help if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)

argparse.ArgumentParser.set_default_subparser = set_default_subparser

def add_network_options(parser):
    parser.add_argument("-1", "--oneserver", action="store_true", dest="oneserver", default=False, help="connect to one server only")
    parser.add_argument("-s", "--server", dest="server", default=None, help="set server host:port:protocol, where protocol is either t (tcp) or s (ssl)")
    parser.add_argument("-p", "--proxy", dest="proxy", default=None, help="set proxy [type:]host[:port], where type is socks4,socks5 or http")

from util import profiler

@profiler
def get_parser(run_gui, run_daemon, run_cmdline):
    # parent parser, because set_default_subparser removes global options
    parent_parser = argparse.ArgumentParser('parent', add_help=False)
    parent_parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Show debugging information")
    parent_parser.add_argument("-P", "--portable", action="store_true", dest="portable", default=False, help="Use local 'electrum-ltc_data' directory")
    # create main parser
    parser = argparse.ArgumentParser(
        parents=[parent_parser],
        epilog="Run 'electrum-ltc help <command>' to see the help for a command")
    subparsers = parser.add_subparsers(dest='cmd', metavar='<command>')
    # gui
    parser_gui = subparsers.add_parser('gui', parents=[parent_parser], description="Run Electrum's Graphical User Interface.", help="Run GUI (default)")
    parser_gui.add_argument("url", nargs='?', default=None, help="litecoin URI (or bip70 file)")
    parser_gui.set_defaults(func=run_gui)
    parser_gui.add_argument("-g", "--gui", dest="gui", help="select graphical user interface", choices=['qt', 'lite', 'gtk', 'text', 'stdio'])
    parser_gui.add_argument("-m", action="store_true", dest="hide_gui", default=False, help="hide GUI on startup")
    parser_gui.add_argument("-L", "--lang", dest="language", default=None, help="default language used in GUI")
    parser_gui.add_argument("-o", "--offline", action="store_true", dest="offline", default=False, help="Run the GUI offline")
    parser_gui.add_argument("-w", "--wallet", dest="wallet_path", help="wallet path")
    add_network_options(parser_gui)
    # daemon
    parser_daemon = subparsers.add_parser('daemon', parents=[parent_parser], help="Run Daemon")
    parser_daemon.add_argument("subcommand", choices=['start', 'status', 'stop'])
    parser_daemon.set_defaults(func=run_daemon)
    add_network_options(parser_daemon)
    # commands
    for cmdname in sorted(known_commands.keys()):
        cmd = known_commands[cmdname]
        p = subparsers.add_parser(cmdname, parents=[parent_parser], help=cmd.help, description=cmd.help + '. ' + cmd.description)
        p.set_defaults(func=run_cmdline)
        if cmd.requires_password:
            p.add_argument("-W", "--password", dest="password", default=None, help="password")
        if cmd.requires_network:
            p.add_argument("-o", "--offline", action="store_true", dest="offline", default=False, help="Run command offline")
        if cmd.requires_wallet:
            p.add_argument("-w", "--wallet", dest="wallet_path", help="wallet path")
        for optname in cmd.options:
            a, b, default, help = command_options[optname]
            action = "store_true" if type(default) is bool else 'store'
            args = (a, b) if a else (b,)
            if action == 'store':
                _type = arg_types.get(optname, str)
                p.add_argument(*args, dest=optname, action=action, default=default, help=help, type=_type)
            else:
                p.add_argument(*args, dest=optname, action=action, default=default, help=help)

        for param in cmd.params:
            h = param_descriptions.get(param, '')
            _type = arg_types.get(param, str)
            p.add_argument(param, help=h, type=_type)
    # 'gui' is the default command
    parser.set_default_subparser('gui')
    return parser
