import hashlib
from collections import defaultdict
from electroncash.bitcoin import (
    bfh, bh2u, MySigningKey, MyVerifyingKey, SECP256k1,
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, Hash,
    pubkey_from_signature, msg_magic, TYPE_ADDRESS)
from electroncash.transaction import Transaction, int_to_hex
from electroncash.address import Address, AddressError
from electroncash.wallet import dust_threshold
from electroncash.util import profiler, PrintError
import ecdsa
from .conf_keys import ConfKeys

class CoinUtils(PrintError):
    """ Utility functions for transactions, blockchain, & electrumx servers. """

    def __init__(self, network):
        assert network, "network is None!"
        self.network = network

    # This method taken from lib/commands.py::Commands
    def getaddressunspent(self, address):
        """Returns the UTXO list of any address. Note: This
        is a walletless server query, results are not checked by SPV.
        """
        if not isinstance(address, Address):
            try:
                address = Address.from_string(address)
            except AddressError:
                return None
        sh = address.to_scripthash_hex()
        return self.network.synchronous_get(('blockchain.scripthash.listunspent', [sh]))

    def check_inputs_for_sufficient_funds_and_return_total(self, inputs, amount):
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
        3. return True, total_amt if summary values of utxos are greater then amount and False, None otherwise
           returns None,None on blockchain communication error
        """
        assert amount > 0, "Amount must be > 0!"
        def _utxo_name(x): return x['tx_hash'] + ":" + str(x['tx_pos'])
        total = 0
        try:
            for public_key, pk_inputs in inputs.items():
                try:
                    address = Address.from_pubkey(public_key)
                except AddressError:
                    # refuse to accept something that doesn't parse as a pubkey
                    return False, None
                unspent_list = self.getaddressunspent(address)
                utxos = {
                    _utxo_name(utxo) : utxo['value']
                    for utxo in unspent_list if utxo.get('height',-1) > 0  # all inputs must have at least 1 confirmation
                }
                for utxo in pk_inputs:
                    val = utxos.get(utxo)
                    if val is None:
                        return False, None # utxo does not exist or was spent
                    total += val
            answer = total >= amount
            if answer:
                return True, total
            return False, total

        except BaseException as e:
            #import traceback
            #traceback.print_exc()
            self.print_error("check_inputs_for_sufficient_funds: ", repr(e))
        return None, None

    def get_coins(self, inputs):
        coins = {}
        for public_key, utxos in inputs.items():
            address = Address.from_pubkey(public_key)
            coins[public_key] = []  # FIXME: Should probably use a defaultdict here but maybe we want calling code to fail on KeyError ?
            unspent_list = self.getaddressunspent(address)
            utxo_dicts = { "{}:{}".format(utxo["tx_hash"], utxo["tx_pos"]) : utxo
                           for utxo in unspent_list }
            for utxo in utxos:
                utxo_dict = utxo_dicts.get(utxo)
                if utxo_dict:
                    coins[public_key].append(utxo_dict)
                else:
                    # uh-oh.. not found. may have been double-spent in the meantimg or buggy Player peer.
                    return None
        return coins


    def dust_threshold(self):
        return dust_threshold(self.network)

    def make_unsigned_transaction(self, amount, fee, all_inputs, outputs, changes):
        ''' make unsigned transaction '''
        dust = self.dust_threshold()  # always 546 for now, but this call is here in case something more sophisticated happens in the future
        coins = {}
        tx_inputs = []
        amounts = {}
        try:
            for player in all_inputs:
                inputs_coins = self.get_coins(all_inputs[player])
                # if there are no coins on input it terminates the process
                if inputs_coins:
                    coins[player] = inputs_coins
                else:
                    return None
        except BaseException as e:
            self.print_error('make_unsigned_transaction:', repr(e))
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

    @staticmethod
    def get_transaction_signature(transaction, inputs, secret_keys):
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

    @staticmethod
    def add_transaction_signatures(transaction, signatures):
        "Add players' signatures to transaction"
        inputs = transaction.inputs()
        for i, txin in enumerate(inputs):
            sig_index = txin['tx_hash'] + ":" + str(txin['tx_pos'])
            if signatures.get(sig_index, None):
                inputs[i]['signatures'] = [signatures[sig_index].decode()]
        transaction.raw = transaction.serialize()

    @staticmethod
    def verify_tx_signature(signature, transaction, verification_key, utxo):
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
        try:
            pk, compressed = pubkey_from_signature(signature, Hash(msg_magic(message)))
            pubkey = point_to_ser(pk.pubkey.point, compressed).hex()
            return pubkey == verification_key
        except Exception as e:
            self.print_error("verify_signature:", repr(e))
            return False

    ###########################################################################
    ### Static methods related to wallet/coins/is_shuffled etc...           ###
    ###########################################################################
    @staticmethod
    def get_name(coin):
        ''' Given a coin dict, return prevout_hash:n as a string. '''
        return "{}:{}".format(coin['prevout_hash'], coin['prevout_n'])

    @staticmethod
    def unfreeze_frozen_by_shuffling(wallet):
        with wallet.lock, wallet.transaction_lock:
            coins_frozen_by_shuffling = wallet.storage.get(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, list())
            if coins_frozen_by_shuffling:
                l = len(coins_frozen_by_shuffling)
                if l: wallet.print_error("Freed {} frozen-by-shuffling UTXOs".format(l))
                wallet.set_frozen_coin_state(coins_frozen_by_shuffling, False)
            wallet.storage.put(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, None) # deletes key altogether from storage

    @staticmethod
    def is_coin_shuffled(wallet, coin, txs_in=None):
        ''' Determine if a coin is shuffled. We determine this based on
            the shape of the tx that produced it.

            Params:
                wallet - wallet instance, preferably shuffle-patched (if the
                         supplied wallet is not patched, the results will not
                         be cached and this function will run slower).
                coin   - dict for the utxo (as created by wallet.py)
                txs_in - the dict of tx_hash -> Transaction instances to use.
                         If none, will grab wallet.transactions.

            We define a shuffled output as:
              - being in a tx where there are at least 2 other outputs of the same amount
              - being in a tx where if you group the outputs by amount, the utxo in question
                belongs to the longest (or tied for longest) group.
              - all output addresses for this group must be different/unique.
        '''
        cache = getattr(wallet, "_is_shuffled_cache", dict())
        tx_id, n = coin['prevout_hash'], coin['prevout_n']
        name = "{}:{}".format(tx_id, n)
        answer = cache.get(name, None)
        if answer is not None:
            # check cache, if cache hit, return answer and avoid the lookup below
            return answer
        def doChk():
            if txs_in:
                txs = txs_in
            else:
                txs = wallet.transactions
            tx = txs.get(tx_id, None)
            if tx is not None:
                outputs = tx.outputs()
                inputs_len = len(tx.inputs())
                if inputs_len < 3:
                    # short-circuit out of here -- too few inputs (min 3 required for shuffling)
                    return False
                amount_groups = defaultdict(list)  # dict of amount(sats) -> list of out_n's of tx (for that amount)
                amount_addresses = defaultdict(set) # dict of amount(sats) -> set of addresses for that amount
                # 1. bin the output-n's by amount spent
                for out_n, output in enumerate(outputs):
                    typ, addr, amount = output  # TODO: do we enforce that typ must be 'p2pkh'?
                    amount_groups[amount].append(out_n)
                    # 2. Remember the set of addresses for this group. This set's length must equal the amount_group length (ensures unique address for each output)
                    amount_addresses[amount].add(addr)
                len_to_group = defaultdict(list)  # dict of group_length -> list of amounts for that length
                for amount, group in amount_groups.items():
                    len_to_group[len(group)].append(amount)
                longest_amounts = len_to_group[max(len_to_group.keys())]
                # 3. Now check that our prevout_n is in one of the longest amount groups in the tx outputs
                for amount in longest_amounts:
                    n_list = amount_groups[amount]
                    if n not in n_list:
                        continue
                    n_list_len = len(n_list)
                    if n_list_len >= 3 and inputs_len >= n_list_len:
                        addr_set = amount_addresses[amount]
                        if len(addr_set) == n_list_len:
                            # bingo! it satisfies all the criteria. mark this as shuffled!
                            return True
                        # else ...
                        #   it would have satisfied the criteria but at least 1 of the outputs goes to a dupe address.
                    break # unconditionally break out of the loop because there is no point in continuing to search. we got our answer -- it's if we get to this point
                return False
            else:
                # Not found in tx_list so its shuffle status is as yet "unknown". Indicate this.
                return None
        # /doChk
        answer = doChk()
        if answer is not None:
            # cache the answer iff it's a definitive answer True/False only
            cache[name] = answer
        return answer

    @staticmethod
    def get_shuffled_and_unshuffled_coin_totals(wallet, exclude_frozen = False, mature = False, confirmed_only = False):
        ''' Returns a 3-tuple of tuples of (amount_total, num_utxos) that are 'shuffled', 'unshuffled' and 'unshuffled_but_in_progress', respectively. '''
        shuf, unshuf, uprog = wallet.get_shuffled_and_unshuffled_coins(exclude_frozen, mature, confirmed_only)
        ret = []
        for l in ( shuf, unshuf, uprog ):
            ret.append( (sum(c['value'] for c in l), len(l)) )
        return tuple(ret)

    # Called from either the wallet code or the shufflethread.
    # The wallet code calls this when spending either shuffled-only or unshuffled-only coins in a tx.
    @staticmethod
    def get_new_change_address_safe(wallet, for_shufflethread=False):
        with wallet.lock, wallet.transaction_lock:
            if not for_shufflethread and wallet._last_change and not wallet.get_address_history(wallet._last_change):
                # if they keep hitting preview on the same tx, give them the same change each time
                return wallet._last_change
            change = None
            for address in wallet.get_unused_addresses(for_change=True):
                if address not in wallet._addresses_cashshuffle_reserved:
                    change = address
                    break
            while not change:
                address = wallet.create_new_address(for_change=True)
                if address not in wallet._addresses_cashshuffle_reserved:
                    change = address
            wallet._addresses_cashshuffle_reserved.add(change)
            if not for_shufflethread:
                # new change address generated for code outside the shuffle threads. cache and return it next time.
                wallet._last_change = change
            return change

    @staticmethod
    @profiler
    def get_shuffled_and_unshuffled_coins(wallet, exclude_frozen = False, mature = False, confirmed_only = False):
        ''' Returns a 3-tupe of mutually exclusive lists: shuffled_utxos, unshuffled_utxos, and unshuffled_but_in_progress '''
        shuf, unshuf, uprog = [], [], []
        if hasattr(wallet, 'is_coin_shuffled'):
            with wallet.lock:
                with wallet.transaction_lock:
                    coins_frozen_by_shuffling = set(wallet.storage.get(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, list()))
                    utxos = wallet.get_utxos(exclude_frozen = exclude_frozen, mature = mature, confirmed_only = confirmed_only)
                    txs = wallet.transactions
                    for utxo in utxos:
                        state = wallet.is_coin_shuffled(utxo, txs)
                        if state:
                            shuf.append(utxo)
                        else:
                            name = __class__.get_name(utxo)
                            if state is not None:
                                if name not in coins_frozen_by_shuffling:
                                    unshuf.append(utxo)
                                else:
                                    uprog.append(utxo)
                            else:
                                wallet.print_error("Warning: get_shuffled_and_unshuffled_coins got an 'unknown' utxo: {}", name)
        return shuf, unshuf, uprog
