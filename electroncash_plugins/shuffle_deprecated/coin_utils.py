import hashlib
from collections import defaultdict
from electroncash.bitcoin import (
    bfh, bh2u, MySigningKey, MyVerifyingKey, SECP256k1,
    generator_secp256k1, point_to_ser, ser_to_point,
    public_key_to_p2pkh, Hash,
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
        transaction = Transaction.from_io(tx_inputs, tx_outputs, sign_schnorr=False)
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
                signatures[txin['tx_hash'] + ":" + str(txin['tx_pos'])] = (bh2u(sig) + '41').encode('utf-8')
        return signatures

    @staticmethod
    def add_transaction_signatures(transaction, signatures):
        "Add players' signatures to transaction"
        inputs = transaction.inputs()
        missing = list()
        for i, txin in enumerate(inputs):
            utxo = "{}:{}".format(txin['tx_hash'], txin['tx_pos'])
            sig = signatures.get(utxo)
            if sig:
                try:
                    txin['signatures'] = [sig.decode()]
                except ValueError:
                    sig = None # Misc. unicode or hex decode error, fall thru...
            if not sig:
                # missing signature or decode error above.
                missing.append((i, utxo))
        transaction.raw = transaction.serialize()
        return missing

    @staticmethod
    def IsValidDERSignatureEncoding_With_Extract(sig):
        ''' sig should be a bytes object of the raw sig data bytes excluding
        sighash byte.
        Returns r,s tuple if it follows STRICTENC, or else raises AssertionError.

        Based on BitcoinABC source code:
        https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/script/sigencoding.cpp#L27
        /**
         * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len
         * S> <S>, where R and S are not negative (their first byte has its highest bit
         * not set), and not excessively padded (do not start with a 0 byte, unless an
         * otherwise negative number follows, in which case a single 0 byte is
         * necessary and even required).
         *
         * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
         *
         * This function is consensus-critical since BIP66.
         */
        '''
        # // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
        # // * total-length: 1-byte length descriptor of everything that follows,
        # // excluding the sighash byte.
        # // * R-length: 1-byte length descriptor of the R value that follows.
        # // * R: arbitrary-length big-endian encoded R value. It must use the
        # // shortest possible encoding for a positive integers (which means no null
        # // bytes at the start, except a single one when the next byte has its
        # // highest bit set).
        # // * S-length: 1-byte length descriptor of the S value that follows.
        # // * S: arbitrary-length big-endian encoded S value. The same rules apply.
        #
        # Some sample inputs to test this function:
        #r=(81592364208652584016851361869694565004145639608376408039883438744265234600879,
        #s=33308936342624208176251215154315566707800991341260116503885941528977175948962,
        #sig='3045022100b463a43fb7f7bb5f68f2cfb4c86bdfdc14cac6eaf13c49b623ca06f04cd853af022049a4309b8c96bace3c536867c0cfc4fa5cbff94cf484385f1e1e623db3632ea2'
        #// Minimum and maximum size constraints.
        def Assert(b):
            ''' We do it this way because if the Python interpreter is run with
            the -O (optimize) option, the keyword 'assert' is a no-op.'''
            if not b:
                raise AssertionError("Invalid DER signature encoding")
        Assert(len(sig) >= 8 and len(sig) <= 72)
        Assert(sig[0] == 0x30)
        Assert(sig[1] == len(sig)-2) # Check length
        Assert(sig[2] == 0x02)
        r_length = sig[3]
        # zero length integers are not allowed
        Assert(r_length > 0)
        r_pos = 4
        # Negative numbers are not allowed for R.
        Assert(not (sig[r_pos] & 0x80))
        # // Make sure the length of the R element is consistent with the signature
        # // size.
        # // Remove:
        # // * 1 byte for the coumpound type.
        # // * 1 byte for the length of the signature.
        # // * 2 bytes for the integer type of R and S.
        # // * 2 bytes for the size of R and S.
        # // * 1 byte for S itself.
        Assert(r_length <= len(sig) - 7)
        # // Null bytes at the start of R are not allowed, unless R would otherwise be
        # // interpreted as a negative number.
        # //
        # // /!\ This check can only be performed after we checked that lenR is
        # //     consistent with the size of the signature or we risk to access out of
        # //     bound elements.
        if r_length > 1 and sig[4] == 0x00:
            Assert(sig[5] & 0x80)
        r = int.from_bytes(sig[r_pos : r_pos + r_length], byteorder='big')

        s_start = r_pos + r_length
        Assert(sig[s_start] == 0x02)
        s_length = sig[s_start+1]
        # zero length integers are not allowed
        Assert(s_length > 0)
        s_pos = s_start+2
        # Negative numbers not allowed
        Assert(not (sig[s_pos] & 0x80))
        #// Verify that the length of S is consistent with the size of the signature
        #// including metadatas:
        #// * 1 byte for the integer type of S.
        #// * 1 byte for the size of S.
        Assert(s_pos + s_length == len(sig))
        #// Null bytes at the start of S are not allowed, unless S would otherwise be
        #// interpreted as a negative number.
        #//
        #// /!\ This check can only be performed after we checked that lenR and lenS
        #//     are consistent with the size of the signature or we risk to access
        #//     out of bound elements.
        if s_length > 1 and sig[s_pos] == 0x00:
            Assert(sig[s_pos + 1] & 0x80)
        s = int.from_bytes(sig[s_pos : s_pos + s_length], byteorder='big')
        return r, s

    @staticmethod
    def verify_tx_signature(signature, transaction, verification_key, utxo):
        '''Verify the signature for a specific utxo ("prevout_hash:n") given a
        transaction and verification key. Ensures that the signature is valid
        AND canonically encoded, so it will be accepted by network.
        '''
        tx_num = None
        for n, x in enumerate(transaction.inputs()):
            if (verification_key in x['pubkeys']
                    and utxo == "{}:{}".format( x['tx_hash'], x['tx_pos'] ) ):
                tx_num = n
                break
        else:
            # verification_key / utxo combo not found in tx inputs, bail
            return False
        # calculate sighash digest (implicitly this is for sighash 0x41)
        pre_hash = Hash(bfh(transaction.serialize_preimage(tx_num)))
        order = generator_secp256k1.order()
        try:
            sigbytes = bfh(signature.decode())
        except ValueError:
            # not properly hex encoded or UnicodeDecodeError (garbage data)
            return False
        if not sigbytes or sigbytes[-1] != 0x41:
            return False
        DERsig = sigbytes[:-1]  # lop off the sighash byte for the DER check below
        try:
            # ensure DER encoding is canonical, and extract r,s if OK
            r, s = CoinUtils.IsValidDERSignatureEncoding_With_Extract(DERsig)
        except AssertionError:
            return False
        if (s << 1) > order:
            # high S values are rejected by BCH network
            return False
        try:
            pubkey_point = ser_to_point(bfh(verification_key))
        except:
            # ser_to_point will fail if pubkey is off-curve, infinity, or garbage.
            return False
        vk = MyVerifyingKey.from_public_point(pubkey_point, curve=SECP256k1)
        try:
            return vk.verify_digest(DERsig, pre_hash, sigdecode = ecdsa.util.sigdecode_der)
        except:
            # verify_digest returns True on success, otherwise raises
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
    def unfreeze_frozen_by_shuffling(wallet, *, write=False):
        with wallet.lock:
            coins_frozen_by_shuffling = wallet.storage.get(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, list())
            if coins_frozen_by_shuffling:
                l = len(coins_frozen_by_shuffling)
                if l: wallet.print_error("Freed {} frozen-by-shuffling UTXOs".format(l))
                wallet.set_frozen_coin_state(coins_frozen_by_shuffling, False)
            wallet.storage.put(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, None) # deletes key altogether from storage
        if write:
            wallet.storage.write()

    @staticmethod
    def store_shuffle_change_shared_with_others(wallet, *, write=False):
        ''' Reads wallet _shuffle_change_shared_with_others and saves
        it to storage. _shuffle_patched_ needs to be set. '''
        if not hasattr(wallet, '_shuffle_patched_'):
            return
        # save _shuffle_change_shared_with_others to storage
        wallet.storage.put(ConfKeys.PerWallet.CHANGE_SHARED_WITH_OTHERS,
                           [a.to_storage_string()
                            for a in wallet._shuffle_change_shared_with_others.copy()])
        if write:
            wallet.storage.write()

    @staticmethod
    def load_shuffle_change_shared_with_others(wallet):
        ''' Modifies wallet instance and adds _shuffle_change_shared_with_others
        retrieving it from storage. _shuffle_patched_ need not be set. '''
        wallet._shuffle_change_shared_with_others = set()
        tmpadrs = wallet.storage.get(ConfKeys.PerWallet.CHANGE_SHARED_WITH_OTHERS, [])
        if isinstance(tmpadrs, (list, tuple, set)):
            for a in tmpadrs:
                try:
                    a = Address.from_string(a)
                    if not wallet.get_address_history(a):  # no need to re-add to set if it has a history since it won't be shared anyway with the network if it's been used. This set is used only to not cross over shuffled out addresses with change addresses for unused addrs when shuffling
                        wallet._shuffle_change_shared_with_others.add(a)
                except (AddressError, TypeError):
                    pass


    @staticmethod
    def coin_name_to_dict(coin_name):
        tok = coin_name.split(':')
        return {
            'prevout_hash' : tok[0],
            'prevout_n'    : int(tok[1])
        }

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
              - being in a tx where there are at least 3 other outputs of the same amount
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
            if answer:
                addr = coin.get('address')  # coin['address'] may be undefined if caller is doing funny stuff.
                # rememebr this address as being a "shuffled" address and cache the positive reply
                if addr: getattr(wallet, "_shuffled_address_cache", set()).add(addr)
        return answer

    @staticmethod
    def is_shuffled_address(wallet, address):
        ''' Returns True if address contains any shuffled UTXOs.
            If you want thread safety, caller must hold wallet locks. '''
        assert isinstance(address, Address)
        cache = getattr(wallet, '_shuffled_address_cache', None)
        if cache is None:
            return False
        if address in cache:
            return True
        utxos = wallet.get_addr_utxo(address)
        for coin in utxos.values():
            if CoinUtils.is_coin_shuffled(wallet, coin):
                cache.add(address)
                return True
        return False

    @staticmethod
    def remove_from_shuffled_address_cache(wallet, addr_set):
        ''' Purges addresses (pass any iterator, preferably a set)
        from the _shuffled_address_cache.
        Caller need not hold any locks (they will be acquired)'''
        if not addr_set:
            return
        if not isinstance(addr_set, set):
            addr_set = set(addr_set)
        with wallet.lock:
            wallet._shuffled_address_cache.difference_update(addr_set)

    @staticmethod
    def remove_from_shufflecache(wallet, utxo_names):
        ''' Purges utxo_names (pass any iterator) from the _is_shuffled_cache.
        Caller need not hold any locks (they will be acquired)'''
        if not utxo_names:
            return
        cache = getattr(wallet, '_is_shuffled_cache', dict())
        if not cache:
            return
        with wallet.lock:
            for name in utxo_names:
                cache.pop(name, None)

    @staticmethod
    def get_shuffled_and_unshuffled_coin_totals(wallet, exclude_frozen = False, mature = False, confirmed_only = False):
        ''' Returns a 4-tuple of tuples of (amount_total, num_utxos) that are:
        'shuffled', 'unshuffled', 'unshuffled_but_in_progress', and
        'unshuffled_but_spend_as_shuffled' respectively. '''
        shuf, unshuf, uprog, usas = wallet.get_shuffled_and_unshuffled_coins(exclude_frozen, mature, confirmed_only)
        ret = []
        for l in ( shuf, unshuf, uprog, usas ):
            ret.append( (sum(c['value'] for c in l), len(l)) )
        return tuple(ret)

    # Called from either the wallet code or the shufflethread.
    # The wallet code calls this when spending either shuffled-only or unshuffled-only coins in a tx.
    # for_shufflethread may be a bool or an int. If int:
    # 0    : not for shuffle threads, use the one wallet-global 'reserved' change guaranteed to not have any history, which won't ever conflict with the shuffle threads (used in 'Send' tab)
    # 1    : for 'change' address use in shuffle threads. This address will be marked as having been 'announced' and will not be eligible to be used as a shuffled output address or in the Send tab as a change address for a user-created TX
    # >=2  : for 'shuffled output' address use in shuffle threads. This address is guaranteed to have never been shared over the network with other shufflers AND to be unused
    @staticmethod
    def get_new_change_address_safe(wallet, for_shufflethread=0):
        for_shufflethread = int(for_shufflethread or 0) # coerce to int in case it was a bool or None
        with wallet.lock:
            if not for_shufflethread and wallet._last_change and not wallet.get_address_history(wallet._last_change):
                # if they keep hitting preview on the same tx, give them the same change each time
                return wallet._last_change
            change = None
            for address in wallet.get_unused_addresses(for_change=True):
                if (address not in wallet._addresses_cashshuffle_reserved
                        and (for_shufflethread == 1 or address not in wallet._shuffle_change_shared_with_others)):
                    change = address
                    break
            while not change:
                address = wallet.create_new_address(for_change=True)
                if (address not in wallet._addresses_cashshuffle_reserved
                        and (for_shufflethread == 1 or address not in wallet._shuffle_change_shared_with_others)):
                    change = address
            wallet._addresses_cashshuffle_reserved.add(change)
            if not for_shufflethread:
                # new change address generated for code outside the shuffle threads. cache and return it next time.
                wallet._last_change = change
            if for_shufflethread == 1:
                # this was either a 'change' output for the shuffle thread
                # Mark it as having been somewhat privacy-reduced so that if
                # this function is called with for_shufflethread=2 or 0, we
                # won't ever give this particular change address out again).
                # See issue clifordsymack#105
                wallet._shuffle_change_shared_with_others.add(change)
            return change

    @staticmethod
    @profiler
    def get_shuffled_and_unshuffled_coins(wallet, exclude_frozen = False, mature = False, confirmed_only = False,
                                          *, no_in_progress_check = False):
        ''' Returns a 4-tuple of mutually exclusive lists:
        shuffled_utxos, unshuffled_utxos, unshuffled_but_in_progress,
        unshuffled_but_spend_as_shuffled '''
        shuf, unshuf, uprog, usas = [], [], [], []  # shuffled, unshuffled, unshuffled_in_progress, unshuffled_spend_as_shuffled
        if hasattr(wallet, 'is_coin_shuffled'):
            with wallet.lock:
                coins_frozen_by_shuffling = set(wallet.storage.get(ConfKeys.PerWallet.COINS_FROZEN_BY_SHUFFLING, list())) if not no_in_progress_check else set()
                utxos = wallet.get_utxos(exclude_frozen = exclude_frozen, mature = mature, confirmed_only = confirmed_only)
                txs = wallet.transactions
                for utxo in utxos:
                    state = wallet.is_coin_shuffled(utxo, txs)  # side-effect is that the _shuffled_address_cache gets updated iff true retval
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
                unshuf_orig = unshuf
                unshuf = []
                for utxo in unshuf_orig:
                    # NEW: Coins that live on shuffled addresses are categorized as "unshuffled: spend as shuffled" and are not eligible for shuffling
                    if utxo['address'] in wallet._shuffled_address_cache:
                        usas.append(utxo)
                    else:
                        unshuf.append(utxo)
        return shuf, unshuf, uprog, usas
