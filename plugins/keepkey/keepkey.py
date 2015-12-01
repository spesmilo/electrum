from binascii import unhexlify
from struct import pack
from sys import stderr
from time import sleep
import unicodedata
import threading
import re
from functools import partial


import electrum_ltc as electrum
from electrum_ltc import bitcoin

from electrum_ltc.account import BIP32_Account
from electrum_ltc.bitcoin import EncodeBase58Check, public_key_to_bc_address, bc_address_to_hash_160, xpub_from_pubkey
from electrum_ltc.i18n import _
from electrum_ltc.plugins import BasePlugin, hook, always_hook, run_hook
from electrum_ltc.transaction import Transaction, deserialize, is_extended_pubkey, x_to_xpub
from electrum_ltc.wallet import BIP32_HD_Wallet
from electrum_ltc.util import print_error, print_msg
from electrum_ltc.wallet import pw_decode, bip32_private_derivation, bip32_root


try:
    from keepkeylib.client import types
    from keepkeylib.client import proto, BaseClient, ProtocolMixin
    from keepkeylib.transport import ConnectionError
    from keepkeylib.transport_hid import HidTransport
    KEEPKEY = True
except ImportError:
    KEEPKEY = False

import keepkeylib.ckd_public as ckd_public

def log(msg):
    stderr.write("%s\n" % msg)
    stderr.flush()

def give_error(message):
    print_error(message)
    raise Exception(message)




class KeepKeyWallet(BIP32_HD_Wallet):
    wallet_type = 'keepkey'
    root_derivation = "m/44'/2'"

    def __init__(self, storage):
        BIP32_HD_Wallet.__init__(self, storage)
        self.mpk = None
        self.device_checked = False
        self.proper_device = False
        self.force_watching_only = False

    def get_action(self):
        if not self.accounts:
            return 'create_accounts'

    def can_import(self):
        return False

    def can_sign_xpubkey(self, x_pubkey):
        xpub, sequence = BIP32_Account.parse_xpubkey(x_pubkey)
        return xpub in self.master_public_keys.values()

    def can_export(self):
        return False

    def can_create_accounts(self):
        return True

    def can_change_password(self):
        return False

    def is_watching_only(self):
        return self.force_watching_only

    def get_client(self):
        return self.plugin.get_client()

    def address_id(self, address):
        account_id, (change, address_index) = self.get_address_index(address)
        return "44'/2'/%s'/%d/%d" % (account_id, change, address_index)

    def create_main_account(self, password):
        self.create_account('Main account', None) #name, empty password

    def mnemonic_to_seed(self, mnemonic, passphrase):
        # keepkey uses bip39
        import pbkdf2, hashlib, hmac
        PBKDF2_ROUNDS = 2048
        mnemonic = unicodedata.normalize('NFKD', ' '.join(mnemonic.split()))
        passphrase = unicodedata.normalize('NFKD', passphrase)
        return pbkdf2.PBKDF2(mnemonic, 'mnemonic' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

    def derive_xkeys(self, root, derivation, password):
        x = self.master_private_keys.get(root)
        if x:
            root_xprv = pw_decode(x, password)
            xprv, xpub = bip32_private_derivation(root_xprv, root, derivation)
            return xpub, xprv
        else:
            derivation = derivation.replace(self.root_name,"44'/2'/")
            xpub = self.get_public_key(derivation)
            return xpub, None

    def get_public_key(self, bip32_path):
        address_n = self.plugin.get_client().expand_path(bip32_path)
        node = self.plugin.get_client().get_public_node(address_n).node
        xpub = "0488B21E".decode('hex') + chr(node.depth) + self.i4b(node.fingerprint) + self.i4b(node.child_num) + node.chain_code + node.public_key
        return EncodeBase58Check(xpub)

    def get_master_public_key(self):
        if not self.mpk:
            self.mpk = self.get_public_key("44'/2'")
        return self.mpk

    def i4b(self, x):
        return pack('>I', x)

    def add_keypairs(self, tx, keypairs, password):
        #do nothing - no priv keys available
        pass

    def decrypt_message(self, pubkey, message, password):
        raise BaseException( _('Decrypt method is not implemented in KeepKey') )
        #address = public_key_to_bc_address(pubkey.decode('hex'))
        #address_path = self.address_id(address)
        #address_n = self.get_client().expand_path(address_path)
        #try:
        #    decrypted_msg = self.get_client().decrypt_message(address_n, b64decode(message))
        #except Exception, e:
        #    give_error(e)
        #finally:
        #    twd.stop()
        #return str(decrypted_msg)

    def sign_message(self, address, message, password):
        if self.has_seed():
            return BIP32_HD_Wallet.sign_message(self, address, message, password)
        if not self.check_proper_device():
            give_error('Wrong device or password')
        try:
            address_path = self.address_id(address)
            address_n = self.plugin.get_client().expand_path(address_path)
        except Exception, e:
            give_error(e)
        try:
            msg_sig = self.plugin.get_client().sign_message('Litecoin', address_n, message)
        except Exception, e:
            give_error(e)
        finally:
            self.plugin.handler.stop()
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if self.has_seed():
            return BIP32_HD_Wallet.sign_transaction(self, tx, password)
        if tx.is_complete():
            return
        if not self.check_proper_device():
            give_error('Wrong device or password')
        # previous transactions used as inputs
        prev_tx = {}
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs:
            tx_hash = txin['prevout_hash']

            ptx = self.transactions.get(tx_hash)
            if ptx is None:
                ptx = self.network.synchronous_get(('blockchain.transaction.get', [tx_hash]))
                ptx = Transaction(ptx)
            prev_tx[tx_hash] = ptx

            for x_pubkey in txin['x_pubkeys']:
                account_derivation = None
                if not is_extended_pubkey(x_pubkey):
                    continue
                xpub = x_to_xpub(x_pubkey)
                for k, v in self.master_public_keys.items():
                    if v == xpub:
                        account_id = re.match("x/(\d+)'", k).group(1)
                        account_derivation = "44'/2'/%s'"%account_id
                if account_derivation is not None:
                    xpub_path[xpub] = account_derivation

        self.plugin.sign_transaction(tx, prev_tx, xpub_path)

    def check_proper_device(self):
        self.get_client().ping('t')
        if not self.device_checked:
            address = self.addresses(False)[0]
            address_id = self.address_id(address)
            n = self.get_client().expand_path(address_id)
            device_address = self.get_client().get_address('Litecoin', n)
            self.device_checked = True

            if device_address != address:
                self.proper_device = False
            else:
                self.proper_device = True

        return self.proper_device



class KeepKeyPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self._is_available = self._init()
        self.wallet = None
        self.handler = None
        self.client = None
        self.transport = None

    def constructor(self, s):
        return KeepKeyWallet(s)

    def _init(self):
        return KEEPKEY

    def is_available(self):
        if not self._is_available:
            return False
        if not self.wallet:
            return False
        if self.wallet.storage.get('wallet_type') != 'keepkey':
            return False
        return True

    def set_enabled(self, enabled):
        self.wallet.storage.put('use_' + self.name, enabled)

    def is_enabled(self):
        if not self.is_available():
            return False
        if self.wallet.has_seed():
            return False
        return True

    def compare_version(self, major, minor=0, patch=0):
        features = self.get_client().features
        v = [features.major_version, features.minor_version, features.patch_version]
        self.print_error('firmware version', v)
        return cmp(v, [major, minor, patch])

    def atleast_version(self, major, minor=0, patch=0):
        return self.compare_version(major, minor, patch) >= 0

    def get_client(self):
        if not KEEPKEY:
            give_error('please install github.com/keepkey/python-keepkey')

        if not self.client or self.client.bad:
            d = HidTransport.enumerate()
            if not d:
                give_error('Could not connect to your KeepKey. Please verify the cable is connected and that no other app is using it.')
            self.transport = HidTransport(d[0])
            self.client = QtGuiKeepKeyClient(self.transport)
            self.client.handler = self.handler
            self.client.set_tx_api(self)
            self.client.bad = False
            if not self.atleast_version(1, 0, 0):
                self.client = None
                give_error('Outdated KeepKey firmware. Please update the firmware from https://www.keepkey.com')
        return self.client

    @hook
    def close_wallet(self):
        print_error("keepkey: clear session")
        if self.client:
            self.client.clear_session()
            self.client.transport.close()
            self.client = None
        self.wallet = None


    def show_address(self, address):
        if not self.wallet.check_proper_device():
            give_error('Wrong device or password')
        try:
            address_path = self.wallet.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception, e:
            give_error(e)
        try:
            self.get_client().get_address('Litecoin', address_n, True)
        except Exception, e:
            give_error(e)
        finally:
            self.handler.stop()


    def sign_transaction(self, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client()
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(tx)
        try:
            signed_tx = client.sign_tx('Litecoin', inputs, outputs)[1]
        except Exception, e:
            self.handler.stop()
            give_error(e)

        self.handler.stop()

        raw = signed_tx.encode('hex')
        tx.update_signatures(raw)


    def tx_inputs(self, tx, for_sig=False):
        inputs = []
        for txin in tx.inputs:
            txinputtype = types.TxInputType()
            if txin.get('is_coinbase'):
                prev_hash = "\0"*32
                prev_index = 0xffffffff # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                        xpub_n = self.get_client().expand_path(self.xpub_path[xpub])
                        txinputtype.address_n.extend(xpub_n + s)
                    else:
                        def f(x_pubkey):
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                            else:
                                xpub = xpub_from_pubkey(x_pubkey.decode('hex'))
                                s = []
                            node = ckd_public.deserialize(xpub)
                            return types.HDNodePathType(node=node, address_n=s)
                        pubkeys = map(f, x_pubkeys)
                        multisig = types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=map(lambda x: x.decode('hex') if x else '', txin.get('signatures')),
                            m=txin.get('num_sig'),
                        )
                        txinputtype = types.TxInputType(
                            script_type=types.SPENDMULTISIG,
                            multisig= multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = self.get_client().expand_path(self.xpub_path[xpub])
                                    txinputtype.address_n.extend(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if 'scriptSig' in txin:
                script_sig = txin['scriptSig'].decode('hex')
                txinputtype.script_sig = script_sig

            if 'sequence' in txin:
                sequence = txin['sequence']
                txinputtype.sequence = sequence

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, tx):
        outputs = []

        for type, address, amount in tx.outputs:
            assert type == 'address'
            txoutputtype = types.TxOutputType()
            if self.wallet.is_change(address):
                address_path = self.wallet.address_id(address)
                address_n = self.get_client().expand_path(address_path)
                txoutputtype.address_n.extend(address_n)
            else:
                txoutputtype.address = address
            txoutputtype.amount = amount
            addrtype, hash_160 = bc_address_to_hash_160(address)
            if addrtype == 48:
                txoutputtype.script_type = types.PAYTOADDRESS
            elif addrtype == 5:
                txoutputtype.script_type = types.PAYTOSCRIPTHASH
            else:
                raise BaseException('addrtype')
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = types.TransactionType()
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']
        inputs = self.tx_inputs(tx)
        t.inputs.extend(inputs)
        for vout in d['outputs']:
            o = t.bin_outputs.add()
            o.amount = vout['value']
            o.script_pubkey = vout['scriptPubKey'].decode('hex')
        return t

    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        tx.deserialize()
        return self.electrum_tx_to_txtype(tx)







class KeepKeyGuiMixin(object):

    def __init__(self, *args, **kwargs):
        super(KeepKeyGuiMixin, self).__init__(*args, **kwargs)

    def callback_ButtonRequest(self, msg):
        if msg.code == 3:
            message = "Confirm transaction outputs on KeepKey device to continue"
        elif msg.code == 8:
            message = "Confirm transaction fee on KeepKey device to continue"
        elif msg.code == 7:
            message = "Confirm message to sign on KeepKey device to continue"
        elif msg.code == 10:
            message = "Confirm address on KeepKey device to continue"
        else:
            message = "Check KeepKey device to continue"
        self.handler.show_message(msg.code, message, self)
        return proto.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 1:
            desc = 'current PIN'
        elif msg.type == 2:
            desc = 'new PIN'
        elif msg.type == 3:
            desc = 'new PIN again'
        else:
            desc = 'PIN'
        pin = self.handler.get_pin("Please enter KeepKey %s" % desc)
        if not pin:
            return proto.Cancel()
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        msg = _("Please enter your KeepKey passphrase.")
        passphrase = self.handler.get_passphrase(msg)
        if passphrase is None:
            return proto.Cancel()
        return proto.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        #TODO
        log("Enter one word of mnemonic: ")
        word = raw_input()
        return proto.WordAck(word=word)



if KEEPKEY:
    class QtGuiKeepKeyClient(ProtocolMixin, KeepKeyGuiMixin, BaseClient):
        def call_raw(self, msg):
            try:
                resp = BaseClient.call_raw(self, msg)
            except ConnectionError:
                self.bad = True
                raise

            return resp

