from binascii import hexlify, unhexlify
import traceback
import sys

from electrum.util import (bfh, bh2u, versiontuple, UserCancelled,
                           UserFacingException)
from electrum.bitcoin import TYPE_ADDRESS, TYPE_SCRIPT
from electrum.bip32 import BIP32Node
from electrum import constants
from electrum.i18n import _
from electrum.plugin import Device
from electrum.transaction import deserialize, Transaction
from electrum.keystore import Hardware_KeyStore, is_xpubkey, parse_xpubkey
from electrum.base_wizard import ScriptTypeNotSupported

from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import (is_any_tx_output_on_change_branch,
                                trezor_validate_op_return_output_and_get_data)


# Hideez initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)
RECOVERY_TYPE_SCRAMBLED_WORDS = range(0, 1)


class HideezKeyStore(Hardware_KeyStore):
    hw_type = 'hideez'
    device = 'Hideez'

    def get_derivation(self):
        return self.derivation

    def get_client(self, force_pair=True):
        return self.plugin.get_client(self, force_pair)

    def decrypt_message(self, sequence, message, password):
        raise UserFacingException(_('Encryption and decryption are not '
                                    'implemented by {}').format(self.device))

    def sign_message(self, sequence, message, password):
        client = self.get_client()
        address_path = self.get_derivation() + ("/%d/%d" % sequence)
        address_n = client.expand_path(address_path)
        msg_sig = client.sign_message(self.plugin.get_coin_name(),
                                      address_n, message)
        return msg_sig.signature

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        # previous transactions used as inputs
        prev_tx = {}
        # path of the xpubs that are involved
        xpub_path = {}
        for txin in tx.inputs():
            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            tx_hash = txin['prevout_hash']
            if txin.get('prev_tx') is None and not Transaction.is_segwit_input(txin):
                raise UserFacingException(_('Offline signing with {} is '
                                            'not supported for legacy '
                                            'inputs.').format(self.device))
            prev_tx[tx_hash] = txin['prev_tx']
            for x_pubkey in x_pubkeys:
                if not is_xpubkey(x_pubkey):
                    continue
                xpub, s = parse_xpubkey(x_pubkey)
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        self.plugin.sign_transaction(self, tx, prev_tx, xpub_path)


class HideezPlugin(HW_PluginBase):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, types

    firmware_URL = 'https://hideez.com'
    libraries_URL = 'https://github.com/HideezGroup/python-hideez'
    minimum_firmware = (1, 7, 3)
    keystore_class = HideezKeyStore
    minimum_library = (0, 2, 1)
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')

    MAX_LABEL_LEN = 32

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)

        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return

        from . import client
        from . import transport
        import hideezlib.messages
        self.client_class = client.HideezClient
        self.types = hideezlib.messages
        self.DEVICE_IDS = ('HIDEEZ',)

        self.transport_handler = transport.HideezTransport()
        self.device_manager().register_enumerate_func(self.enumerate)

    def get_library_version(self):
        import hideezlib
        try:
            return hideezlib.__version__
        except AttributeError:
            return 'unknown'

    def enumerate(self):
        devices = self.transport_handler.enumerate_devices()
        return [Device(path=d.get_path(),
                       interface_number=-1,
                       id_=d.get_path(),
                       product_key='HIDEEZ',
                       usage_page=0,
                       transport_ui_string=d.get_path())
                for d in devices]

    def create_client(self, device, handler):
        try:
            self.logger.info(f"connecting to device at {device.path}")
            transport = self.transport_handler.get_transport(device.path)
        except BaseException as e:
            self.logger.info(f"cannot connect at {device.path} {e}")
            return None

        if not transport:
            self.logger.info(f"cannot connect at {device.path}")
            return

        self.logger.info(f"connected to device at {device.path}")
        client = self.client_class(transport, handler, self)

        # Try a ping for device sanity
        try:
            client.ping('t')
        except BaseException as e:
            self.logger.info(f"ping failed {e}")
            return None

        if not client.atleast_version(*self.minimum_firmware):
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                   .format(self.device, client.label(), self.firmware_URL))
            self.logger.info(msg)
            if handler:
                handler.show_error(msg)
            else:
                raise UserFacingException(msg)
            return None

        return client

    def get_client(self, keystore, force_pair=True):
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler,
                                                keystore, force_pair)
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def get_coin_name(self):
        return "Testnet" if constants.net.TESTNET else "Bitcoin"

    def _make_node_path(self, xpub, address_n):
        bip32node = BIP32Node.from_xkey(xpub)
        node = self.types.HDNodeType(
            depth=bip32node.depth,
            fingerprint=int.from_bytes(bip32node.fingerprint, 'big'),
            child_num=int.from_bytes(bip32node.child_number, 'big'),
            chain_code=bip32node.chaincode,
            public_key=bip32node.eckey.get_public_key_bytes(compressed=True),
        )
        return self.types.HDNodePathType(node=node, address_n=address_n)

    def setup_device(self, device_info, wizard, purpose):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise UserFacingException(_('Failed to create a client '
                                        'for this device.') + '\n' +
                                      _('Make sure it is in the '
                                        'correct state.'))
        # fixme: we should use: client.handler = wizard
        client.handler = self.create_handler(wizard)
        client.init_device()
        if not client.is_initialized():
            msg = _("Hideez Wallet is not initialized.\n\n"
                    "To initialize your Hideez Wallet please switch to "
                    "Hideez Bridge window and do device initialization "
                    "and backup sequence.\n\n"
                    "When device initialization and backup is finished "
                    "press 'Next' to proceed.")
            raise UserFacingException(msg)
        client.get_xpub('m', 'standard')
        client.used()

    def get_xpub(self, device_id, derivation, xtype, wizard):
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script '
                                           'is not supported with '
                                           '{}.').format(self.device))
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = wizard
        xpub = client.get_xpub(derivation, xtype)
        client.used()
        return xpub

    def get_hideez_input_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.InputScriptType.SPENDWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.InputScriptType.SPENDP2SHWITNESS
        if electrum_txin_type in ('p2pkh', ):
            return self.types.InputScriptType.SPENDADDRESS
        if electrum_txin_type in ('p2sh', ):
            return self.types.InputScriptType.SPENDMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def get_hideez_output_script_type(self, electrum_txin_type: str):
        if electrum_txin_type in ('p2wpkh', 'p2wsh'):
            return self.types.OutputScriptType.PAYTOWITNESS
        if electrum_txin_type in ('p2wpkh-p2sh', 'p2wsh-p2sh'):
            return self.types.OutputScriptType.PAYTOP2SHWITNESS
        if electrum_txin_type in ('p2pkh', ):
            return self.types.OutputScriptType.PAYTOADDRESS
        if electrum_txin_type in ('p2sh', ):
            return self.types.OutputScriptType.PAYTOMULTISIG
        raise ValueError('unexpected txin type: {}'.format(electrum_txin_type))

    def sign_transaction(self, keystore, tx, prev_tx, xpub_path):
        self.prev_tx = prev_tx
        self.xpub_path = xpub_path
        client = self.get_client(keystore)
        inputs = self.tx_inputs(tx, True)
        outputs = self.tx_outputs(keystore.get_derivation(), tx)
        signatures = client.sign_tx(self.get_coin_name(), inputs,
                                    outputs, lock_time=tx.locktime,
                                    version=tx.version)[0]
        signatures = [(bh2u(x) + '01') for x in signatures]
        tx.update_signatures(signatures)

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        client = self.get_client(keystore)
        if not client.atleast_version(1, 3):
            keystore.handler.show_error(_("Your device firmware is too old"))
            return
        change, index = wallet.get_address_index(address)
        derivation = keystore.derivation
        address_path = "%s/%d/%d" % (derivation, change, index)
        address_n = client.expand_path(address_path)
        xpubs = wallet.get_master_public_keys()
        if len(xpubs) == 1:
            script_type = self.get_hideez_input_script_type(wallet.txin_type)
            client.get_address(self.get_coin_name(), address_n,
                               True, script_type=script_type)
        else:
            def f(xpub):
                return self._make_node_path(xpub, [change, index])
            pubkeys = wallet.get_public_keys(address)
            # sort xpubs using the order of pubkeys
            sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
            pubkeys = list(map(f, sorted_xpubs))
            multisig = self.types.MultisigRedeemScriptType(
               pubkeys=pubkeys,
               signatures=[b''] * wallet.n,
               m=wallet.m,
            )
            script_type = self.get_hideez_input_script_type(wallet.txin_type)
            client.get_address(self.get_coin_name(), address_n, True,
                               multisig=multisig, script_type=script_type)

    def tx_inputs(self, tx, for_sig=False):
        inputs = []
        for txin in tx.inputs():
            txinputtype = self.types.TxInputType()
            if txin['type'] == 'coinbase':
                prev_hash = b"\x00"*32
                prev_index = 0xffffffff  # signed int -1
            else:
                if for_sig:
                    x_pubkeys = txin['x_pubkeys']
                    if len(x_pubkeys) == 1:
                        x_pubkey = x_pubkeys[0]
                        xpub, s = parse_xpubkey(x_pubkey)
                        xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                        txinputtype._extend_address_n(xpub_n + s)
                        txinputtype.script_type = self.get_hideez_input_script_type(txin['type'])
                    else:
                        def f(x_pubkey):
                            xpub, s = parse_xpubkey(x_pubkey)
                            return self._make_node_path(xpub, s)
                        pubkeys = list(map(f, x_pubkeys))
                        multisig = self.types.MultisigRedeemScriptType(
                            pubkeys=pubkeys,
                            signatures=list(map(lambda x:
                                                bfh(x)[:-1] if x else b'',
                                                txin.get('signatures'))),
                            m=txin.get('num_sig'),
                        )
                        script_type = self.get_hideez_input_script_type(txin['type'])
                        txinputtype = self.types.TxInputType(
                            script_type=script_type,
                            multisig=multisig
                        )
                        # find which key is mine
                        for x_pubkey in x_pubkeys:
                            if is_xpubkey(x_pubkey):
                                xpub, s = parse_xpubkey(x_pubkey)
                                if xpub in self.xpub_path:
                                    xpub_n = self.client_class.expand_path(self.xpub_path[xpub])
                                    txinputtype._extend_address_n(xpub_n + s)
                                    break

                prev_hash = unhexlify(txin['prevout_hash'])
                prev_index = txin['prevout_n']

            if 'value' in txin:
                txinputtype.amount = txin['value']
            txinputtype.prev_hash = prev_hash
            txinputtype.prev_index = prev_index

            if txin.get('scriptSig') is not None:
                script_sig = bfh(txin['scriptSig'])
                txinputtype.script_sig = script_sig

            txinputtype.sequence = txin.get('sequence', 0xffffffff - 1)

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, derivation, tx):

        def create_output_by_derivation():
            script_type = self.get_hideez_output_script_type(info.script_type)
            if len(xpubs) == 1:
                address_n = self.client_class.expand_path(derivation + "/%d/%d" % index)
                txoutputtype = self.types.TxOutputType(
                    amount=amount,
                    script_type=script_type,
                    address_n=address_n,
                )
            else:
                address_n = self.client_class.expand_path("/%d/%d" % index)
                pubkeys = [self._make_node_path(xpub, address_n)
                           for xpub in xpubs]
                multisig = self.types.MultisigRedeemScriptType(
                    pubkeys=pubkeys,
                    signatures=[b''] * len(pubkeys),
                    m=m)
                txoutputtype = self.types.TxOutputType(
                    multisig=multisig,
                    amount=amount,
                    address_n=self.client_class.expand_path(derivation + "/%d/%d" % index),
                    script_type=script_type)
            return txoutputtype

        def create_output_by_address():
            txoutputtype = self.types.TxOutputType()
            txoutputtype.amount = amount
            if _type == TYPE_SCRIPT:
                txoutputtype.script_type = self.types.OutputScriptType.PAYTOOPRETURN
                txoutputtype.op_return_data = trezor_validate_op_return_output_and_get_data(o)
            elif _type == TYPE_ADDRESS:
                txoutputtype.script_type = self.types.OutputScriptType.PAYTOADDRESS
                txoutputtype.address = address
            return txoutputtype

        outputs = []
        has_change = False
        any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)

        for o in tx.outputs():
            _type, address, amount = o.type, o.address, o.value
            use_create_by_derivation = False

            info = tx.output_info.get(address)
            if info is not None and not has_change:
                index, xpubs, m = info.address_index, info.sorted_xpubs, info.num_sig
                on_change_branch = index[0] == 1
                # prioritise hiding outputs on the 'change' branch from user
                # because no more than one change address allowed
                # note: ^ restriction can be removed once we require fw
                # that has https://github.com/trezor/trezor-mcu/pull/306
                if on_change_branch == any_output_on_change_branch:
                    use_create_by_derivation = True
                    has_change = True

            if use_create_by_derivation:
                txoutputtype = create_output_by_derivation()
            else:
                txoutputtype = create_output_by_address()
            outputs.append(txoutputtype)

        return outputs

    def electrum_tx_to_txtype(self, tx):
        t = self.types.TransactionType()
        if tx is None:
            # probably for segwit input and we don't need this prev txn
            return t
        d = deserialize(tx.raw)
        t.version = d['version']
        t.lock_time = d['lockTime']
        inputs = self.tx_inputs(tx)
        t._extend_inputs(inputs)
        for vout in d['outputs']:
            o = t._add_bin_outputs()
            o.amount = vout['value']
            o.script_pubkey = bfh(vout['scriptPubKey'])
        return t

    # This function is called from the Hideez libraries (via tx_api)
    def get_tx(self, tx_hash):
        tx = self.prev_tx[tx_hash]
        return self.electrum_tx_to_txtype(tx)
