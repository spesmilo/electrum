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

import os
import sys
import datetime
import time
import copy
import argparse
import json
import ast
from functools import wraps
from decimal import Decimal

import util
from util import print_msg, format_satoshis, print_stderr
import bitcoin
from bitcoin import is_address, hash_160_to_bc_address, hash_160, COIN
from transaction import Transaction
import paymentrequest
from paymentrequest import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED

known_commands = {}

class Command:

    def __init__(self, func, s):
        self.name = func.__name__
        self.requires_network = 'n' in s
        self.requires_wallet = 'w' in s
        self.requires_password = 'p' in s
        self.description = func.__doc__
        self.help = self.description.split('.')[0]
        varnames = func.func_code.co_varnames[1:func.func_code.co_argcount]
        self.defaults = func.func_defaults
        if self.defaults:
            n = len(self.defaults)
            self.params = list(varnames[:-n])
            self.options = list(varnames[-n:])
        else:
            self.params = list(varnames)
            self.options = []
            self.defaults = []


def command(s):
    def decorator(func):
        global known_commands
        name = func.__name__
        known_commands[name] = Command(func, s)
        @wraps(func)
        def func_wrapper(*args):
            return func(*args)
        return func_wrapper
    return decorator


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

    @command('')
    def help(self):
        """Print help"""
        return 'Commands: ' + ', '.join(sorted(known_commands.keys()))

    @command('')
    def create(self):
        """Create a new wallet"""

    @command('')
    def restore(self):
        """Restore a wallet from seed. """

    @command('')
    def deseed(self):
        """Remove seed from wallet. This creates a seedless, watching-only
        wallet."""

    @command('wp')
    def password(self):
        """Change wallet password. """

    @command('')
    def getconfig(self, key):
        """Return a configuration variable. """
        return self.config.get(key)

    @command('')
    def setconfig(self, key, value):
        """Set a configuration variable. 'value' may be a string or a Python expression."""
        try:
            value = ast.literal_eval(value)
        except:
            pass
        self.config.set_key(key, value)
        return True

    @command('')
    def make_seed(self, nbits=128, entropy=1, language=None):
        """Create a seed"""
        from mnemonic import Mnemonic
        s = Mnemonic(language).make_seed(nbits, custom_entropy=entropy)
        return s.encode('utf8')

    @command('')
    def check_seed(self, seed, entropy=1, language=None):
        """Check that a seed was generated with given entropy"""
        from mnemonic import Mnemonic
        return Mnemonic(language).check_seed(seed, entropy)

    @command('n')
    def getaddresshistory(self, address):
        """Return the transaction history of any address. Note: This is a
        walletless server query, results are not checked by SPV.
        """
        return self.network.synchronous_get([('blockchain.address.get_history', [address])])[0]

    @command('nw')
    def listunspent(self):
        """List unspent outputs. Returns the list of unspent transaction
        outputs in your wallet."""
        l = copy.deepcopy(self.wallet.get_spendable_coins(exclude_frozen = False))
        for i in l: i["value"] = str(Decimal(i["value"])/COIN)
        return l

    @command('n')
    def getaddressunspent(self, address):
        """Returns the UTXO list of any address. Note: This
        is a walletless server query, results are not checked by SPV.
        """
        return self.network.synchronous_get([('blockchain.address.listunspent', [address])])[0]

    @command('n')
    def getutxoaddress(self, txid, pos):
        """Get the address of a UTXO. Note: This is a walletless server query, results are
        not checked by SPV.
        """
        r = self.network.synchronous_get([('blockchain.utxo.get_address', [txid, pos])])
        if r:
            return {'address':r[0]}

    @command('wp')
    def createrawtx(self, inputs, outputs, unsigned=False):
        """Create a transaction from json inputs. The syntax is similar to bitcoind."""
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
        outputs = map(lambda x: ('address', x[0], int(COIN*x[1])), outputs.items())
        tx = Transaction.from_io(tx_inputs, outputs)
        if not unsigned:
            self.wallet.sign_transaction(tx, self.password)
        return tx

    @command('wp')
    def signtransaction(self, tx, privkey=None):
        """Sign a transaction. The wallet keys will be used unless a private key is provided."""
        t = Transaction(tx)
        t.deserialize()
        if privkey:
            pubkey = bitcoin.public_key_from_private_key(sec)
            t.sign({pubkey:sec})
        else:
            self.wallet.sign_transaction(t, self.password)
        return t

    @command('')
    def deserialize(self, tx):
        """Deserialize a serialized transaction"""
        t = Transaction(tx)
        return t.deserialize()

    @command('n')
    def broadcast(self, tx):
        """Broadcast a transaction to the network. """
        t = Transaction(tx)
        return self.network.synchronous_get([('blockchain.transaction.broadcast', [str(t)])])[0]

    @command('')
    def createmultisig(self, num, pubkeys):
        """Create multisig address"""
        assert isinstance(pubkeys, list), (type(num), type(pubkeys))
        redeem_script = Transaction.multisig_script(pubkeys, num)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return {'address':address, 'redeemScript':redeem_script}

    @command('w')
    def freeze(self, address):
        """Freeze address. Freeze the funds at one of your wallet\'s addresses"""
        return self.wallet.set_frozen_state([address], True)

    @command('w')
    def unfreeze(self, address):
        """Unfreeze address. Unfreeze the funds at one of your wallet\'s address"""
        return self.wallet.set_frozen_state([address], False)

    @command('wp')
    def getprivatekeys(self, address):
        """Get the private keys of an address. Address must be in wallet."""
        return self.wallet.get_private_key(address, self.password)

    @command('w')
    def ismine(self, address):
        """Check if address is in wallet. Return true if and only address is in wallet"""
        return self.wallet.is_mine(address)

    @command('wp')
    def dumpprivkeys(self, domain=None):
        """Dump private keys from your wallet"""
        if domain is None:
            domain = self.wallet.addresses(True)
        return [self.wallet.get_private_key(address, self.password) for address in domain]

    @command('')
    def validateaddress(self, address):
        """Check that the address is valid. """
        return is_address(address)

    @command('w')
    def getpubkeys(self, address):
        """Return the public keys for a wallet address. """
        return self.wallet.get_public_keys(address)

    @command('nw')
    def getbalance(self, account=None):
        """Return the balance of your wallet"""
        if account is None:
            c, u, x = self.wallet.get_balance()
        else:
            c, u, x = self.wallet.get_account_balance(account)
        out = {"confirmed": str(Decimal(c)/COIN)}
        if u:
            out["unconfirmed"] = str(Decimal(u)/COIN)
        if x:
            out["unmatured"] = str(Decimal(x)/COIN)
        return out

    @command('n')
    def getaddressbalance(self, address):
        """Return the balance of any address. Note: This is a walletless
        server query, results are not checked by SPV.
        """
        out = self.network.synchronous_get([('blockchain.address.get_balance', [address])])[0]
        out["confirmed"] =  str(Decimal(out["confirmed"])/COIN)
        out["unconfirmed"] =  str(Decimal(out["unconfirmed"])/COIN)
        return out

    @command('n')
    def getproof(self, address):
        """Get Merkle branch of an address in the UTXO set"""
        p = self.network.synchronous_get([('blockchain.address.get_proof', [address])])[0]
        out = []
        for i,s in p:
            out.append(i)
        return out

    @command('n')
    def getmerkle(self, txid, height):
        """Get Merkle branch of a transaction included in a block"""
        return self.network.synchronous_get([('blockchain.transaction.get_merkle', [txid, int(height)])])[0]

    @command('n')
    def getservers(self):
        """Return the list of available servers"""
        while not self.network.is_up_to_date():
            time.sleep(0.1)
        return self.network.get_servers()

    @command('')
    def version(self):
        """Return the version of electrum."""
        import electrum  # Needs to stay here to prevent ciruclar imports
        return electrum.ELECTRUM_VERSION

    @command('w')
    def getmpk(self):
        """Get Master Public Key. Return your wallet\'s master public key"""
        return self.wallet.get_master_public_keys()

    @command('wp')
    def getseed(self):
        """Get seed phrase. Print the generation seed of your wallet."""
        s = self.wallet.get_mnemonic(self.password)
        return s.encode('utf8')

    @command('wp')
    def importprivkey(self, privkey):
        """Import a private key. """
        try:
            addr = self.wallet.import_key(privkey, self.password)
            out = "Keypair imported: ", addr
        except Exception as e:
            out = "Error: Keypair import failed: " + str(e)
        return out

    def _resolver(self, x):
        if x is None:
            return None
        out = self.contacts.resolve(x)
        if out.get('type') == 'openalias' and self.nocheck is False and out.get('validated') is False:
            raise BaseException('cannot verify alias', x)
        return out['address']

    @command('n')
    def sweep(self, privkey, destination, tx_fee=None, nocheck=False):
        """Sweep private key. Returns a transaction that spends UTXOs from
        privkey to a destination address. The transaction is not
        broadcasted."""
        self.nocheck = nocheck
        dest = self._resolver(destination)
        if tx_fee is None:
            tx_fee = 0.0001
        fee = int(Decimal(tx_fee)*COIN)
        return Transaction.sweep([privkey], self.network, dest, fee)

    @command('wp')
    def signmessage(self, address, message):
        """Sign a message with a key. Use quotes if your message contains
        whitespaces"""
        return self.wallet.sign_message(address, message, self.password)

    @command('')
    def verifymessage(self, address, signature, message):
        """Verify a signature."""
        return bitcoin.verify_message(address, signature, message)

    def _mktx(self, outputs, fee, change_addr, domain, nocheck, unsigned):
        self.nocheck = nocheck
        change_addr = self._resolver(change_addr)
        domain = None if domain is None else map(self._resolver, domain)
        fee = None if fee is None else int(COIN*Decimal(fee))
        final_outputs = []
        for address, amount in outputs:
            address = self._resolver(address)
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
                amount = int(COIN*Decimal(amount))
            final_outputs.append(('address', address, amount))

        coins = self.wallet.get_spendable_coins(domain)
        tx = self.wallet.make_unsigned_transaction(coins, final_outputs, fee, change_addr)
        str(tx) #this serializes
        if not unsigned:
            self.wallet.sign_transaction(tx, self.password)
        return tx

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

    @command('wp')
    def payto(self, destination, amount, tx_fee=None, from_addr=None, change_addr=None, nocheck=False, unsigned=False, deserialized=False, broadcast=False):
        """Create a transaction. """
        domain = [from_addr] if from_addr else None
        tx = self._mktx([(destination, amount)], tx_fee, change_addr, domain, nocheck, unsigned)
        if broadcast:
            r, h = self.wallet.sendtx(tx)
            return h
        else:
            return tx.deserialize() if deserialized else tx

    @command('wp')
    def paytomany(self, csv_file, tx_fee=None, from_addr=None, change_addr=None, nocheck=False, unsigned=False, deserialized=False, broadcast=False):
        """Create a multi-output transaction. """
        domain = [from_addr] if from_addr else None
        outputs = self._read_csv(csv_file)
        tx = self._mktx(outputs, tx_fee, change_addr, domain, nocheck, unsigned)
        if broadcast:
            r, h = self.wallet.sendtx(tx)
            return h
        else:
            return tx.deserialize() if deserialized else tx

    @command('wn')
    def history(self):
        """Wallet history. Returns the transaction history of your wallet."""
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

    @command('w')
    def setlabel(self, key, label):
        """Assign a label to an item. Item may be a bitcoin address or a
        transaction ID"""
        self.wallet.set_label(key, label)

    @command('')
    def listcontacts(self):
        """Show your list of contacts"""
        return self.contacts

    @command('')
    def getalias(self, key):
        """Retrieve alias. Lookup in your list of contacts, and for an OpenAlias DNS record."""
        return self.contacts.resolve(key)

    @command('')
    def searchcontacts(self, query):
        """Search through contacts, return matching entries. """
        results = {}
        for key, value in self.contacts.items():
            if query.lower() in key.lower():
                results[key] = value
        return results

    @command('w')
    def listaddresses(self, receiving=False, change=False, show_labels=False, frozen=False, unused=False, funded=False, show_balance=False):
        """List wallet addresses. Returns your list of addresses."""
        out = []
        for addr in self.wallet.addresses(True):
            if frozen and not self.wallet.is_frozen(addr):
                continue
            if receiving and self.wallet.is_change(addr):
                continue
            if change and not self.wallet.is_change(addr):
                continue
            if unused and self.wallet.is_used(addr):
                continue
            if funded and self.wallet.is_empty(addr):
                continue
            item = addr
            if show_balance:
                item += ", "+ format_satoshis(sum(self.wallet.get_addr_balance(addr)))
            if show_labels:
                item += ', ' + repr(self.wallet.labels.get(addr, ''))
            out.append(item)
        return out

    @command('nw')
    def gettransaction(self, txid, deserialized=False):
        """Retrieve a transaction. """
        tx = self.wallet.transactions.get(txid) if self.wallet else None
        if tx is None and self.network:
            raw = self.network.synchronous_get([('blockchain.transaction.get', [txid])])[0]
            if raw:
                tx = Transaction(raw)
            else:
                raise BaseException("Unknown transaction")
        return tx.deserialize() if deserialized else tx

    @command('')
    def encrypt(self, pubkey, message):
        """Encrypt a message with a public key. Use quotes if the message contains whitespaces."""
        return bitcoin.encrypt_message(message, pubkey)

    @command('wp')
    def decrypt(self, pubkey, encrypted):
        """Decrypt a message encrypted with a public key."""
        return self.wallet.decrypt_message(pubkey, encrypted, self.password)

    def _format_request(self, out):
        pr_str = {
            PR_UNKNOWN: 'Unknown',
            PR_UNPAID: 'Pending',
            PR_PAID: 'Paid',
            PR_EXPIRED: 'Expired',
        }
        out['amount'] = format_satoshis(out.get('amount')) + ' BTC'
        out['status'] = pr_str[out.get('status', PR_UNKNOWN)]
        return out

    @command('wn')
    def getrequest(self, key):
        """Return a payment request"""
        r = self.wallet.get_payment_request(key, self.config)
        if not r:
            raise BaseException("Request not found")
        return self._format_request(r)

    #@command('w')
    #def ackrequest(self, serialized):
    #    """<Not implemented>"""
    #    pass

    @command('wn')
    def listrequests(self, pending=False, expired=False, paid=False):
        """List the payment requests you made."""
        out = self.wallet.get_sorted_requests(self.config)
        if pending:
            f = PR_UNPAID
        elif expired:
            f = PR_EXPIRED
        elif paid:
            f = PR_PAID
        else:
            f = None
        if f:
            out = filter(lambda x: x.get('status')==f, out)
        return map(self._format_request, out)

    @command('w')
    def addrequest(self, requested_amount, memo='', expiration=60*60, force=False):
        """Create a payment request."""
        addr = self.wallet.get_unused_address(None)
        if addr is None:
            if force:
                addr = self.wallet.create_new_address(None, False)
            else:
                return False
        amount = int(Decimal(requested_amount)*COIN)
        req = self.wallet.add_payment_request(addr, amount, memo, expiration, self.config)
        return self._format_request(req)

    @command('w')
    def rmrequest(self, key):
        """Remove a payment request"""
        return self.wallet.remove_payment_request(key, self.config)

param_descriptions = {
    'privkey': 'Private key. Type \'?\' to get a prompt.',
    'destination': 'Bitcoin address, contact or alias',
    'address': 'Bitcoin address',
    'seed': 'Seed phrase',
    'txid': 'Transaction ID',
    'pos': 'Position',
    'height': 'Block height',
    'tx': 'Serialized transaction (hexadecimal)',
    'key': 'Variable name',
    'pubkey': 'Public key',
    'message': 'Clear text message. Use quotes if it contains spaces.',
    'encrypted': 'Encrypted message',
    'amount': 'Amount to be sent (in BTC). Type \'!\' to send the maximum available.',
    'requested_amount': 'Requested amount (in BTC).',
    'csv_file': 'CSV file of recipient, amount',
}

command_options = {
    'broadcast':   (None, "--broadcast",   "Broadcast the transaction to the Bitcoin network"),
    'password':    ("-W", "--password",    "Password"),
    'concealed':   ("-C", "--concealed",   "Don't echo seed to console when restoring"),
    'receiving':   (None, "--receiving",   "Show only receiving addresses"),
    'change':      (None, "--change",      "Show only change addresses"),
    'frozen':      (None, "--frozen",      "Show only frozen addresses"),
    'unused':      (None, "--unused",      "Show only unused addresses"),
    'funded':      (None, "--funded",      "Show only funded addresses"),
    'show_balance':("-b", "--balance",     "Show the balances of listed addresses"),
    'show_labels': ("-l", "--labels",      "Show the labels of listed addresses"),
    'nocheck':     (None, "--nocheck",     "Do not verify aliases"),
    'tx_fee':      ("-f", "--fee",         "Transaction fee (in BTC)"),
    'from_addr':   ("-F", "--from",        "Source address. If it isn't in the wallet, it will ask for the private key unless supplied in the format public_key:private_key. It's not saved in the wallet."),
    'change_addr': ("-c", "--change",      "Change address. Default is a spare address, or the source address if it's not in the wallet"),
    'nbits':       (None, "--nbits",       "Number of bits of entropy"),
    'entropy':     (None, "--entropy",     "Custom entropy"),
    'language':    ("-L", "--lang",        "Default language for wordlist"),
    'gap_limit':   ("-G", "--gap",         "Gap limit"),
    'mpk':         (None, "--mpk",         "Restore from master public key"),
    'deserialized':("-d", "--deserialized","Return deserialized transaction"),
    'privkey':     (None, "--privkey",     "Private key. Set to '?' to get a prompt."),
    'unsigned':    ("-u", "--unsigned",    "Do not sign transaction"),
    'domain':      ("-D", "--domain",      "List of addresses"),
    'account':     (None, "--account",     "Account"),
    'memo':        ("-m", "--memo",        "Description of the request"),
    'expiration':  (None, "--expiration",  "Time in seconds"),
    'force':       (None, "--force",       "Create new address beyong gap limit, if no more address is available."),
    'pending':     (None, "--pending",     "Show only pending requests."),
    'expired':     (None, "--expired",     "Show only expired requests."),
    'paid':        (None, "--paid",        "Show only paid requests."),
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

config_variables = {

    'addrequest': {
        'requests_dir': 'directory where a bip70 file will be written.',
        'ssl_privkey': 'Path to your SSL private key, needed to sign the request.',
        'ssl_chain': 'Chain of SSL certificates, needed for signed requests. Put your certificate at the top and the root CA at the end',
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of bitcoin: URIs. Example: \"(\'file:///var/www/\',\'https://electrum.org/\')\"',
    },
    'listrequests':{
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of bitcoin: URIs. Example: \"(\'file:///var/www/\',\'https://electrum.org/\')\"',
    }
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
    group = parent_parser.add_argument_group('global options')
    group.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Show debugging information")
    group.add_argument("-P", "--portable", action="store_true", dest="portable", default=False, help="Use local 'electrum_data' directory")
    group.add_argument("-w", "--wallet", dest="wallet_path", help="wallet path")
    group.add_argument("-o", "--offline", action="store_true", dest="offline", default=False, help="Run offline")
    # create main parser
    parser = argparse.ArgumentParser(
        parents=[parent_parser],
        epilog="Run 'electrum help <command>' to see the help for a command")
    subparsers = parser.add_subparsers(dest='cmd', metavar='<command>')
    # gui
    parser_gui = subparsers.add_parser('gui', parents=[parent_parser], description="Run Electrum's Graphical User Interface.", help="Run GUI (default)")
    parser_gui.add_argument("url", nargs='?', default=None, help="bitcoin URI (or bip70 file)")
    parser_gui.set_defaults(func=run_gui)
    parser_gui.add_argument("-g", "--gui", dest="gui", help="select graphical user interface", choices=['qt', 'lite', 'gtk', 'text', 'stdio', 'jsonrpc'])
    parser_gui.add_argument("-m", action="store_true", dest="hide_gui", default=False, help="hide GUI on startup")
    parser_gui.add_argument("-L", "--lang", dest="language", default=None, help="default language used in GUI")
    add_network_options(parser_gui)
    # daemon
    parser_daemon = subparsers.add_parser('daemon', parents=[parent_parser], help="Run Daemon")
    parser_daemon.add_argument("subcommand", choices=['start', 'status', 'stop'])
    parser_daemon.set_defaults(func=run_daemon)
    add_network_options(parser_daemon)
    # commands
    for cmdname in sorted(known_commands.keys()):
        cmd = known_commands[cmdname]
        p = subparsers.add_parser(cmdname, parents=[parent_parser], help=cmd.help, description=cmd.description)
        p.set_defaults(func=run_cmdline)
        if cmd.requires_password:
            p.add_argument("-W", "--password", dest="password", default=None, help="password")
        for optname, default in zip(cmd.options, cmd.defaults):
            a, b, help = command_options[optname]
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

        cvh = config_variables.get(cmdname)
        if cvh:
            group = p.add_argument_group('configuration variables', '(set with setconfig/getconfig)')
            for k, v in cvh.items():
                group.add_argument(k, nargs='?', help=v)

    # 'gui' is the default command
    parser.set_default_subparser('gui')
    return parser
