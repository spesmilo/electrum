import re
from binascii import unhexlify
from struct import pack

from electrum.account import BIP32_Account
from electrum.bitcoin import (bc_address_to_hash_160, xpub_from_pubkey,
                              EncodeBase58Check)
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import (deserialize, is_extended_pubkey,
                                  Transaction, x_to_xpub)
from electrum.wallet import BIP32_HD_Wallet, BIP44_Wallet

class TrezorCompatibleWallet(BIP44_Wallet):
    # Extend BIP44 Wallet as required by hardware implementation.
    # Derived classes must set:
    #   - device
    #   - wallet_type

    restore_wallet_class = BIP44_Wallet

    def __init__(self, storage):
        BIP44_Wallet.__init__(self, storage)
        self.checked_device = False
        self.proper_device = False

    def give_error(self, message):
        self.print_error(message)
        raise Exception(message)

    def get_action(self):
        if not self.accounts:
            return 'create_accounts'

    def can_export(self):
        return False

    def is_watching_only(self):
        assert not self.has_seed()
        return not self.proper_device

    def can_change_password(self):
        return False

    def get_client(self):
        return self.plugin.get_client()

    def derive_xkeys(self, root, derivation, password):
        if self.master_public_keys.get(root):
            return BIP44_wallet.derive_xkeys(self, root, derivation, password)

        # Happens when creating a wallet
        derivation = derivation.replace(self.root_name, self.prefix() + "/")
        xpub = self.get_public_key(derivation)
        return xpub, None

    def get_public_key(self, bip32_path):
        address_n = self.get_client().expand_path(bip32_path)
        node = self.get_client().get_public_node(address_n).node
        xpub = ("0488B21E".decode('hex') + chr(node.depth)
                + self.i4b(node.fingerprint) + self.i4b(node.child_num)
                + node.chain_code + node.public_key)
        return EncodeBase58Check(xpub)

    def i4b(self, x):
        return pack('>I', x)

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Decrypt method is not implemented'))

    def sign_message(self, address, message, password):
        self.check_proper_device()
        try:
            address_path = self.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception as e:
            self.give_error(e)
        try:
            msg_sig = self.get_client().sign_message('Bitcoin', address_n,
                                                     message)
        except Exception as e:
            self.give_error(e)
        finally:
            self.plugin.handler.stop()
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete() or self.is_watching_only():
            return
        self.check_proper_device()
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
                if not is_extended_pubkey(x_pubkey):
                    continue
                xpub = x_to_xpub(x_pubkey)
                for k, v in self.master_public_keys.items():
                    if v == xpub:
                        acc_id = re.match("x/(\d+)'", k).group(1)
                        xpub_path[xpub] = self.account_derivation(acc_id)

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)

    def is_proper_device(self):
        self.get_client().ping('t')

        if not self.checked_device:
            address = self.addresses(False)[0]
            address_id = self.address_id(address)
            n = self.get_client().expand_path(address_id)
            device_address = self.get_client().get_address('Bitcoin', n)
            self.checked_device = True
            self.proper_device = (device_address == address)

        return self.proper_device

    def check_proper_device(self):
        if not self.is_proper_device():
            self.give_error(_('Wrong device or password'))

    def sanity_check(self):
        try:
            self.get_client().ping('t')
        except BaseException as e:
            return _("%s device not detected.  Continuing in watching-only "
                     "mode.") % self.device + "\n\n" + str(e)

        if self.addresses() and not self.is_proper_device():
            return _("This wallet does not match your %s device") % self.device

        return None

class TrezorCompatiblePlugin(BasePlugin):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.device = self.wallet_class.device
        self.handler = None
        self.client = None

    def constructor(self, s):
        return self.wallet_class(s)

    def give_error(self, message):
        self.print_error(message)
        raise Exception(message)

    def is_enabled(self):
        return self.libraries_available

    def create_client(self):
        if not self.libraries_available:
            self.give_error(_('please install the %s libraries from %s')
                            % (self.device, self.libraries_URL))

        devices = self.HidTransport.enumerate()
        if not devices:
            self.give_error(_('Could not connect to your %s. Please '
                              'verify the cable is connected and that no '
                              'other app is using it.' % self.device))

        transport = self.HidTransport(devices[0])
        client = self.client_class(transport, self)
        if not client.atleast_version(*self.minimum_firmware):
            self.give_error(_('Outdated %s firmware. Please update the '
                              'firmware from %s')
                            % (self.device, self.firmware_URL))
        return client

    def get_client(self):
        if not self.client or self.client.bad:
            self.client = self.create_client()

        return self.client

    def atleast_version(self, major, minor=0, patch=0):
        return self.get_client().atleast_version(major, minor, patch)

    @hook
    def close_wallet(self, wallet):
        if self.client:
            self.print_error("clear session")
            self.client.clear_session()
            self.client.transport.close()
            self.client = None

    def sign_transaction(self, wallet, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client()
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(wallet, tx)
        try:
            signed_tx = client.sign_tx('Bitcoin', inputs, outputs)[1]
        except Exception as e:
            self.give_error(e)
        finally:
            self.handler.stop()
        raw = signed_tx.encode('hex')
        tx.update_signatures(raw)

    def show_address(self, wallet, address):
        client = self.get_client()
        wallet.check_proper_device()
        try:
            address_path = wallet.address_id(address)
            address_n = client.expand_path(address_path)
        except Exception as e:
            self.give_error(e)
        try:
            client.get_address('Bitcoin', address_n, True)
        except Exception as e:
            self.give_error(e)
        finally:
            self.handler.stop()

    def tx_inputs(self, tx, for_sig=False):
        client = self.get_client()
        inputs = []
        for txin in tx.inputs:
            txinputtype = self.types.TxInputType()
            if txin.get('is_coinbase'):
                prev_hash = "\0"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                        xpub_n = client.expand_path(self.xpub_path[xpub])
                        txinputtype.address_n.extend(xpub_n + s)
                    else:
                        def f(x_pubkey):
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                            else:
                                xpub = xpub_from_pubkey(x_pubkey.decode('hex'))
                                s = []
                            node = ckd_public.deserialize(xpub)
                            return self.types.HDNodePathType(node=node, address_n=s)
                        pubkeys = map(f, x_pubkeys)
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=map(lambda x: x.decode('hex') if x else '', txin.get('signatures')),
                            m=txin.get('num_sig'),
                        )
                        txinputtype = self.types.TxInputType(
                            script_type=self.types.SPENDMULTISIG,
                            multisig=multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_extended_pubkey(x_pubkey):
                                xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = client.expand_path(self.xpub_path[xpub])
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

    def tx_outputs(self, wallet, tx):
        client = self.get_client()
        outputs = []

        for type, address, amount in tx.outputs:
            assert type == 'address'
            txoutputtype = self.types.TxOutputType()
            if wallet.is_change(address):
                address_path = wallet.address_id(address)
                address_n = client.expand_path(address_path)
                txoutputtype.address_n.extend(address_n)
            else:
                txoutputtype.address = address
            txoutputtype.amount = amount
            addrtype, hash_160 = bc_address_to_hash_160(address)
            if addrtype == 0:
                txoutputtype.script_type = self.types.PAYTOADDRESS
            elif addrtype == 5:
                txoutputtype.script_type = self.types.PAYTOSCRIPTHASH
            else:
                raise BaseException('addrtype')
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = self.types.TransactionType()
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

    # This function is called from the trezor libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        tx.deserialize()
        return self.electrum_tx_to_txtype(tx)
