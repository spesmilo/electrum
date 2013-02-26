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

protected_commands = ['payto', 'password', 'mktx', 'get_seed', 'importprivkey','signmessage', 'signrawtransaction','dumpprivkey' ]

class Commands:

    def __init__(self, wallet, interface):
        self.wallet = wallet
        self.interface = interface

    def _run(self, method, args, password_getter):
        if method in protected_commands:
            self.password = apply(password_getter,())
        f = eval('self.'+method)
        apply(f,args)
        self.password = None

    def get_history(self, addr):
        h = self.wallet.get_history(addr)
        if h is None: h = self.wallet.interface.synchronous_get([ ('blockchain.address.get_history',[addr]) ])[0]
        print_json(h)

    def listunspent(self):
        print_json(self.wallet.get_unspent_coins())

    def createrawtransaction(self, inputs, outputs):
        # convert to own format
        for i in inputs:
            i['tx_hash'] = i['txid']
            i['index'] = i['vout']
        outputs = map(lambda x: (x[0],int(1e8*x[1])), outputs.items())
        tx = Transaction.from_io(inputs, outputs)
        print_msg( tx )

    def signrawtransaction(self, raw_tx, input_info, private_keys):
        tx = Transaction(raw_tx)
        unspent_coins = self.wallet.get_unspent_coins()

        # convert private_keys to dict 
        pk = {}
        for sec in private_keys:
            address = bitcoin.address_from_private_key(sec)
            pk[address] = sec
        private_keys = pk

        for txin in tx.inputs:
            # convert to own format
            txin['tx_hash'] = txin['prevout_hash']
            txin['index'] = txin['prevout_n']

            for item in input_info:
                if item.get('txid') == txin['tx_hash'] and item.get('vout') == txin['index']:
                    txin['raw_output_script'] = item['scriptPubKey']
                    txin['redeemScript'] = item.get('redeemScript')
                    txin['electrumKeyID'] = item.get('electrumKeyID')
                    break
            else:
                for item in unspent_coins:
                    if txin['tx_hash'] == item['tx_hash'] and txin['index'] == item['index']:
                        txin['raw_output_script'] = item['raw_output_script']
                        break
                else:
                    # if neither, we might want to get it from the server..
                    raise

            # find the address:
            import deserialize
            if txin.get('electrumKeyID'):
                n, for_change = txin.get('electrumKeyID')
                sec = wallet.sequence.get_private_key(n, for_change, seed)
                address = bitcoin.address_from_private_key(sec)
                txin['address'] = address
                private_keys[address] = sec

            elif txin.get("redeemScript"):
                txin['address'] = bitcoin.hash_160_to_bc_address(bitcoin.hash_160(txin.get("redeemScript").decode('hex')), 5)

            elif txin.get("raw_output_script"):
                addr = deserialize.get_address_from_output_script(txin.get("raw_output_script").decode('hex'))
                sec = wallet.get_private_key(addr, self.password)
                if sec: 
                    private_keys[addr] = sec
                    txin['address'] = addr

        tx.sign( private_keys )
        print_json({ "hex":str(tx),"complete":tx.is_complete})

    def decoderawtransaction(self, raw):
        tx = Transaction(raw)
        print_json( tx.deserialize() )

    def sendrawtransaction(self, raw):
        tx = Transaction(raw)
        r, h = wallet.sendtx( tx )
        print_msg(h)

    def createmultisig(self, num, pubkeys):
        assert isinstance(pubkeys, list)
        print_json( Transaction.multisig_script(pubkeys, num) )
    
    def freeze(self,addr):
        print_msg(self.wallet.freeze(addr))
        
    def unfreeze(self,addr):
        print_msg(self.wallet.unfreeze(addr))

    def prioritize(self, addr):
        print_msg(self.wallet.prioritize(addr))

    def unprioritize(self, addr):
        print_msg(self.wallet.unprioritize(addr))

    def dumpprivkey(self, addr):
        sec = self.wallet.get_private_key(addr, self.password)
        print_msg( sec )

    def validateaddress(self,addr):
        is_valid = self.wallet.is_valid(addr)
        out = { 'isvalid':is_valid }
        if is_valid:
            is_mine = self.wallet.is_mine(addr)
            out['address'] = addr
            out['ismine'] = is_mine
            if is_mine:
                out['pubkey'] = self.wallet.get_public_key(addr)
            
        print_json(out)

        
    def balance(self, addresses = []):
        if addresses == []:
            c, u = self.wallet.get_balance()
            if u:
                print_msg(Decimal( c ) / 100000000 , Decimal( u ) / 100000000)
            else:
                print_msg(Decimal( c ) / 100000000)
        else:
            for addr in addresses:
                c, u = wallet.get_addr_balance(addr)
                if u:
                    print_msg("%s %s, %s" % (addr, str(Decimal(c)/100000000), str(Decimal(u)/100000000)))
                else:
                    print_msg("%s %s" % (addr, str(Decimal(c)/100000000)))


    def get_seed(self):
        import mnemonic
        seed = self.wallet.decode_seed(self.password)
        print_msg(seed + ' "' + ' '.join(mnemonic.mn_encode(seed)) + '"')

    def importprivkey(self, sec):
        try:
            addr = wallet.import_key(sec,self.password)
            wallet.save()
            print_msg("Keypair imported: ", addr)
        except BaseException as e:
            print_msg("Error: Keypair import failed: " + str(e))


    def sign_message(self, address, message):
        print_msg(self.wallet.sign_message(address, message, self.password))


    def verify_message(self, address, signature, message):
        try:
            EC_KEY.verify_message(address, signature, message)
            print_msg(True)
        except BaseException as e:
            print_error("Verification error: {0}".format(e))
            print_msg(False)


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
        tx = self._mktx(to_address, amount, fee = None, change_addr = None, from_addr = None)
        out = {"hex":str(tx), "complete":tx.is_complete}
        if not tx.is_complete: 
            out['input_info'] = repr(tx.input_info).replace(' ','')
        print_json(out)


    def payto(self, to_address, amount, fee = None, change_addr = None, from_addr = None):
        tx = self._mktx(to_address, amount, fee = None, change_addr = None, from_addr = None)
        r, h = wallet.sendtx( tx )
        print_msg(h)


    def history(self):
        import datetime
        balance = 0
        for item in self.wallet.get_tx_history():
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            try:
                time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
            except:
                time_str = "----"

            label, is_default_label = self.wallet.get_label(tx_hash)
            if not label: label = tx_hash
            else: label = label + ' '*(64 - len(label) )

            print_msg("%17s"%time_str, "  " + label + "  " + format_satoshis(value)+ "  "+ format_satoshis(balance))
        print_msg("# balance: ", format_satoshis(balance))


    def setlabel(self, tx, label):
        self.wallet.labels[tx] = label
        self.wallet.save()
            

    def contacts(self):
        c = {}
        for addr in self.wallet.addressbook:
            c[addr] = self.wallet.labels.get(addr)
        print_json(c)

