import hashlib
from electroncash.bitcoin import (
    bfh, bh2u, MySigningKey, MyVerifyingKey, SECP256k1,
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, Hash,
    pubkey_from_signature, msg_magic, TYPE_ADDRESS)
from electroncash.transaction import Transaction, int_to_hex
from electroncash.address import Address
from electroncash.wallet import dust_threshold
import ecdsa
from .client import PrintErrorThread


class CoinUtils(PrintErrorThread):
    """ Utility functions for transactions, blockchain, & electrumx servers. """

    def __init__(self, network):
        self.network = network

    # This method taken from lib/commands.py::Commands
    def getaddressunspent(self, address):
        """Returns the UTXO list of any address. Note: This
        is a walletless server query, results are not checked by SPV.
        """
        sh = address.to_scripthash_hex()
        return self.network.synchronous_get(('blockchain.scripthash.listunspent', [sh]))

    def check_inputs_for_sufficient_funds(self, inputs, amount):
        """
        This function check on blockchain for sufficient funds.

        inputs is a dict with bitcoin pubkeys as a keys
        and list of utxo hashes as values.

        the sum of all utxo values should be greater then amount

        it does as follows:
        1. check utxo list for every pubkey in the dict
        2. check if utxo from inputs are in the utxo list on blockchain for these pubkeys
            2.a return None if there is a utxo from list not in utxo set from blockchain
            2.b return None if utxo in list is not confirmed
        3. return True if summary values of utxos are greater then amount and False otherwise
        """
        def _utxo_name(x): return x['tx_hash'] + ":" + str(x['tx_pos'])
        total = 0
        try:
            for public_key, pk_inputs in inputs.items():
                address = Address.from_pubkey(public_key)
                unspent_list = self.getaddressunspent(address)
                utxos = {
                    _utxo_name(utxo) : utxo['value']
                    for utxo in unspent_list if utxo.get('height',-1) > 0  # all inputs must have at least 1 confirmation
                }
                for utxo in pk_inputs:
                    val = utxos.get(utxo)
                    if val is None:
                        return None
                    total += val
            return total >= amount
        except:
            return None

    def get_coins(self, inputs):
        coins = {}
        for public_key in inputs:
            address = Address.from_pubkey(public_key)
            coins[public_key] = []
            unspent_list = self.getaddressunspent(address)
            utxo_hashes = {(utxo["tx_hash"] + ":" + str(utxo["tx_pos"])):utxo for utxo in unspent_list}
            for utxo in inputs[public_key]:
                if utxo in utxo_hashes:
                    coins[public_key].append(utxo_hashes[utxo])
                else:
                    return None
        return coins


    def make_unsigned_transaction(self, amount, fee, all_inputs, outputs, changes):
        "make unsigned transaction"
        dust = dust_threshold(self.network)
        coins = {}
        tx_inputs = []
        amounts = {}
        try:
            for player in all_inputs:
                inputs_coins = self.get_coins(all_inputs[player])
                # if there is no coins on input it terminates the process
                if inputs_coins:
                    coins[player] = inputs_coins
                else:
                    return None
        except:
            return None
        for player, pubkey_utxos in coins.items():
            amounts[player] = 0
            for pubkey, utxos in pubkey_utxos.items():
                for utxo in utxos:
                    utxo['type'] = 'p2pkh'
                    utxo['address'] = Address.from_pubkey(pubkey)
                    utxo['pubkeys'] = [pubkey]
                    utxo['x_pubkeys'] = [pubkey]
                    utxo['prevout_hash'] = utxo['tx_hash']
                    utxo['prevout_n'] = utxo['tx_pos']
                    utxo['signatures'] = [None]
                    utxo['num_sig'] = 1
                    tx_inputs.append(utxo)
                    amounts[player] += utxo['value']
        tx_inputs.sort(key=lambda x: x['prevout_hash']+str(x["tx_pos"]))
        tx_outputs = [(TYPE_ADDRESS, Address.from_string(output), int(amount))
                      for output in outputs]
        transaction = Transaction.from_io(tx_inputs, tx_outputs)
        tx_changes = [(TYPE_ADDRESS, Address.from_string(changes[player]), int(amounts[player] - amount - fee))
                      for player in sorted(changes)
                      if Address.is_valid(changes[player]) and int(amounts[player] - amount - fee) >= dust]
        transaction.add_outputs(tx_changes)
        return transaction

    def get_transaction_signature(self, transaction, inputs, secret_keys):
        "get transaction signature"
        signatures = {}
        for txin in transaction.inputs():
            pubkey = txin['pubkeys'][0]
            if pubkey in inputs:
                tx_num = transaction.inputs().index(txin)
                pre_hash = Hash(bfh(transaction.serialize_preimage(tx_num)))
                private_key = MySigningKey.from_secret_exponent(secret_keys[pubkey].secret, curve=SECP256k1)
                public_key = private_key.get_verifying_key()
                sig = private_key.sign_digest_deterministic(pre_hash,
                                                            hashfunc=hashlib.sha256,
                                                            sigencode=ecdsa.util.sigencode_der)
                assert public_key.verify_digest(sig, pre_hash, sigdecode=ecdsa.util.sigdecode_der)
                signatures[txin['tx_hash'] + ":" + str(txin['tx_pos'])] = (bh2u(sig) + int_to_hex(transaction.nHashType() & 255, 1)).encode('utf-8')
        return signatures

    def add_transaction_signatures(self, transaction, signatures):
        "Add players' signatures to transaction"
        inputs = transaction.inputs()
        for i, txin in enumerate(inputs):
            sig_index = txin['tx_hash'] + ":" + str(txin['tx_pos'])
            if signatures.get(sig_index, None):
                inputs[i]['signatures'] = [signatures[sig_index].decode()]
        transaction.raw = transaction.serialize()


    def verify_tx_signature(self, signature, transaction, verification_key, utxo):
        '''Verify the signature for a specific utxo ("prevout_hash:n") given a
        transaction and verification key.'''
        txin = list(filter(lambda x: (verification_key in x['pubkeys']
                                      and utxo == "{}:{}".format( x['tx_hash'],
                                                                  x['tx_pos'] )
                                      ),
                           transaction.inputs() ))
        if txin:
            tx_num = transaction.inputs().index(txin[0])
            pre_hash = Hash(bfh(transaction.serialize_preimage(tx_num)))
            order = generator_secp256k1.order()
            r, s = ecdsa.util.sigdecode_der(bfh(signature.decode()[:-2]), order)
            sig_string = ecdsa.util.sigencode_string(r, s, order)
            compressed = len(verification_key) <= 66
            for recid in range(0, 4):
                try:
                    pubk = MyVerifyingKey.from_signature(sig_string, recid,
                                                         pre_hash, curve=SECP256k1)
                    pubkey = bh2u(point_to_ser(pubk.pubkey.point, compressed))
                    if verification_key == pubkey:
                        return True
                except:
                    continue
        else:
            return False

    def broadcast_transaction(self, transaction):
        err = "Not connected."
        if self.network and self.network.is_connected():
            try:
                return self.network.broadcast_transaction(transaction)
            except BaseException as e:
                err = "Exception on broadcast: {}".format(str(e))
        return False, err

    def verify_signature(self, signature, message, verification_key):
        "This method verifies signature of message"
        pk, compressed = pubkey_from_signature(signature, Hash(msg_magic(message)))
        pubkey = point_to_ser(pk.pubkey.point, compressed).hex()
        return pubkey == verification_key
