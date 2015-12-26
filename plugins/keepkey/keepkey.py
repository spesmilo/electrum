from binascii import unhexlify

import electrum
from electrum import bitcoin

from electrum.account import BIP32_Account
from electrum.bitcoin import bc_address_to_hash_160, xpub_from_pubkey
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import deserialize, is_extended_pubkey
from electrum.wallet import BIP32_Hardware_Wallet
from electrum.util import print_error
from plugins.trezor.gui_mixin import GuiMixin

try:
    from keepkeylib.client import types
    from keepkeylib.client import proto, BaseClient, ProtocolMixin
    from keepkeylib.transport import ConnectionError
    from keepkeylib.transport_hid import HidTransport
    KEEPKEY = True
except ImportError:
    KEEPKEY = False

import keepkeylib.ckd_public as ckd_public

def give_error(message):
    print_error(message)
    raise Exception(message)


class KeepKeyWallet(BIP32_Hardware_Wallet):
    wallet_type = 'keepkey'
    root_derivation = "m/44'/0'"
    device = 'KeepKey'


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
        self.wallet.check_proper_device()
        try:
            address_path = self.wallet.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception, e:
            give_error(e)
        try:
            self.get_client().get_address('Bitcoin', address_n, True)
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
            signed_tx = client.sign_tx('Bitcoin', inputs, outputs)[1]
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
            if addrtype == 0:
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

if KEEPKEY:
    class QtGuiKeepKeyClient(ProtocolMixin, GuiMixin, BaseClient):
        protocol = proto
        device = 'KeepKey'

        def call_raw(self, msg):
            try:
                resp = BaseClient.call_raw(self, msg)
            except ConnectionError:
                self.bad = True
                raise

            return resp
