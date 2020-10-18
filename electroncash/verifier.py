# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2012 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from abc import ABC, abstractmethod
from .util import ThreadJob, bh2u
from .bitcoin import Hash, hash_decode, hash_encode
from . import networks
from .transaction import Transaction

class BadResponse(Exception): pass

class SPVDelegate(ABC):
    ''' Abstract base class for an object that is SPV-able, such as a wallet.
    wallet.py 'Abstract_Wallet' implements this interface, as does the
    CashAccount subsystem which also has its own private SPV verifier running.

    The verifier (SPV) class later in this file relies on this interface to
    know what to verify. '''

    @abstractmethod
    def get_unverified_txs(self) -> dict:
        ''' Return a dict of tx_hash (hex encoded) -> height (int)'''

    @abstractmethod
    def add_verified_tx(self, tx_hash : str, height_ts_pos_tup : tuple, header : dict) -> None:
        ''' Called when a verification is successful.
        Params:
            #1 tx_hash - hex string
            #2 tuple of: (tx_height: int, timestamp: int, pos : int)
            #3 the header - dict. This can be subsequently serialized using
               blockchain.serialize_header if so desiered, or it can be ignored.
        '''

    @abstractmethod
    def is_up_to_date(self) -> bool:
        ''' Called periodically to determine if more verifications are forth-
        coming.

        If True is returned:
                1. save_verified_tx will then be called,
                2. and the network 'wallet_updated' callback will fire.

        Return False if you do not want the above to happen and/or if you
        have more work for the SPV to do in the near future. '''

    @abstractmethod
    def save_verified_tx(self, write : bool = False):
        ''' Called if is_up_to_date returns True to tell wallet to save verified
        tx's '''

    @abstractmethod
    def undo_verifications(self, blkchain : object, height : int) -> set:
        ''' Called when the blockchain has changed to tell the wallet to undo
        verifications when a reorg has happened. Returns a set of tx_hashes that
        were undone.'''

    @abstractmethod
    def verification_failed(self, tx_hash : str, reason : str):
        ''' Called by verifier when server did return a response but the tx
        in question could not be verified. Reason is one of SPV.failure_reasons'''

    @abstractmethod
    def diagnostic_name(self):
        ''' Make sure delegate classes have this method (PrintError interface). '''

class SPV(ThreadJob):
    """ Simple Payment Verification """

    def __init__(self, network, wallet):
        assert isinstance(wallet, SPVDelegate), "Verifier instance needs to be passed a wallet that is an object implementing the SPVDelegate interface."
        self.wallet = wallet  # despite the name, might not always be a wallet instance, may be SPVDelete (CashAcct)
        self.network = network
        self.blockchain = network.blockchain()
        self.merkle_roots = {}  # txid -> merkle root (once it has been verified)
        self.requested_merkle = set()  # txid set of pending requests
        self.qbusy = False
        self.cleaned_up = False
        self._need_release = False
        self._tick_ct = 0

    def diagnostic_name(self):
        return f"{__class__.__name__}/{self.wallet.diagnostic_name()}"

    def _release(self):
        ''' Called from the Network (DaemonThread) -- to prevent race conditions
        with network, we remove data structures related to the network and
        unregister ourselves as a job from within the Network thread itself. '''
        self._need_release = False
        self.cleaned_up = True
        self.network.cancel_requests(self.verify_merkle)
        self.network.remove_jobs([self])

    def release(self):
        ''' Called from main thread, enqueues a 'release' to happen in the
        Network thread. '''
        self._need_release = True

    def run(self):
        if self._need_release:
            self._release()
        if self.cleaned_up:
            return

        if not self._tick_ct:
            self.print_error("started")
        self._tick_ct += 1

        interface = self.network.interface
        if not interface:
            self.spam_error("v.no interface")
            return

        blockchain = interface.blockchain
        if not blockchain:
            self.spam_error("v.no blockchain", interface.server)
            return

        local_height = self.network.get_local_height()
        unverified = self.wallet.get_unverified_txs()
        for tx_hash, tx_height in unverified.items():
            # do not request merkle branch if we already requested it
            if tx_hash in self.requested_merkle or tx_hash in self.merkle_roots:
                continue
            # or before headers are available
            if tx_height <= 0 or tx_height > local_height:
                continue

            # if it's in the checkpoint region, we still might not have the header
            header = blockchain.read_header(tx_height)
            if header is None:
                if tx_height <= networks.net.VERIFICATION_BLOCK_HEIGHT:
                    # Per-header requests might be a lot heavier.
                    # Also, they're not supported as header requests are
                    # currently designed for catching up post-checkpoint headers.
                    index = tx_height // 2016
                    if self.network.request_chunk(interface, index):
                        interface.print_error("verifier requesting chunk {} for height {}".format(index, tx_height))
                continue
            # enqueue request
            msg_id = self.network.get_merkle_for_transaction(tx_hash, tx_height,
                                                             self.verify_merkle)
            self.qbusy = msg_id is None
            if self.qbusy:
                # interface queue busy, will try again later
                break
            self.print_error('requested merkle', tx_hash)
            self.requested_merkle.add(tx_hash)

        if self.network.blockchain() != self.blockchain:
            self.blockchain = self.network.blockchain()
            self.undo_verifications()

    failure_reasons = (
        'inner_node_tx', 'missing_header', 'merkle_mismatch', 'error_response',
        'misc_failure', 'tx_not_found'
    )

    def verify_merkle(self, response):
        if self.cleaned_up:
            return  # we have been killed, this was just a delayed callback
        try:
            params = response.get('params')
            tx_hash = params and params[0]
            if response.get('error'):
                e = str(response.get('error'))
                if 'not in block' in e.lower():
                    raise BadResponse(self.failure_reasons[5], str(response))
                raise BadResponse('received an error response: ' + str(response))
            merkle = response.get('result')
            if (not isinstance(merkle, dict) or not tx_hash
                    or any(k not in merkle for k in ('block_height', 'merkle', 'pos'))):
                raise BadResponse(f"missing data in response {response}")
        except BadResponse as e:
            freason = self.failure_reasons[3]
            if len(e.args) == 2:
                freason = e.args[0]
             # FIXME: tx will never verify now until switching blockchains or
             # app restart
            if tx_hash:
                self.wallet.verification_failed(tx_hash, freason)
            self.print_error("verify_merkle:", str(e))
            return

        try:
            # Verify the hash of the server-provided merkle branch to a
            # transaction matches the merkle root of its block
            tx_height = merkle['block_height']
            pos = merkle['pos']
            merkle_root = self.hash_merkle_root(merkle['merkle'], tx_hash, pos)
        except Exception as e:
            self.print_error(f"exception while verifying tx {tx_hash}: {repr(e)}")
            self.wallet.verification_failed(tx_hash, self.failure_reasons[4])
            return

        header = self.network.blockchain().read_header(tx_height)
        # FIXME: if verification fails below,
        # we should make a fresh connection to a server to
        # recover from this, as this TX will now never verify
        if not header:
            self.print_error(
                "merkle verification failed for {} (missing header {})"
                .format(tx_hash, tx_height))
            self.wallet.verification_failed(tx_hash, self.failure_reasons[1])
            return
        if header.get('merkle_root') != merkle_root:
            self.print_error(
                "merkle verification failed for {} (merkle root mismatch {} != {})"
                .format(tx_hash, header.get('merkle_root'), merkle_root))
            self.wallet.verification_failed(tx_hash, self.failure_reasons[2])
            return
        # we passed all the tests
        self.merkle_roots[tx_hash] = merkle_root
        # note: we could pop in the beginning, but then we would request
        # this proof again in case of verification failure from the same server
        self.requested_merkle.discard(tx_hash)
        self.print_error("verified %s" % tx_hash)
        self.wallet.add_verified_tx(tx_hash, (tx_height, header.get('timestamp'), pos), header)
        if self.is_up_to_date() and self.wallet.is_up_to_date() and not self.qbusy:
            self.wallet.save_verified_tx(write=True)
            self.network.trigger_callback('wallet_updated', self.wallet)  # This callback will happen very rarely.. mostly right as the last tx is verified. It's to ensure GUI is updated fully.

    @classmethod
    def hash_merkle_root(cls, merkle_s, target_hash, pos):
        h = hash_decode(target_hash)
        for i, item in enumerate(merkle_s):
            h = Hash(hash_decode(item) + h) if ((pos >> i) & 1) else Hash(h + hash_decode(item))
            # An attack was once upon a time possible for SPV, before Nov. 2018
            # which is described here:
            #
            # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-June/016105.html
            # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20180609/9f4f5b1f/attachment-0001.pdf
            # https://bitcoin.stackexchange.com/questions/76121/how-is-the-leaf-node-weakness-in-merkle-trees-exploitable/76122#76122
            #
            # As such, at this point we used to verify the inner node didn't
            # "look" like a tx using some heuristics (which had a very small
            # chance of returning false positives, about 1 in quadrillion).
            #
            # We no longer need do the "inner node looks like tx" check here,
            # however, since no such attack has occurred on the BTC or BCH chain
            # before Nov. 2018. After Nov. 2018 the tx size is now required to
            # be >= 100 bytes which is larger than the 64 byte size of inner
            # nodes.  Thus, the check is rendered superfluous as the attack
            # itself is now no longer even possible after Nov. 2018's hard fork,
            # and so was removed.
            #
            # TL;DR: There used to be some strange check here. It's gone now.
            # Check git history if you're really curious. :)
        return hash_encode(h)

    def undo_verifications(self):
        height = self.blockchain.get_base_height()
        tx_hashes = self.wallet.undo_verifications(self.blockchain, height)
        for tx_hash in tx_hashes:
            self.print_error("redoing", tx_hash)
            self.remove_spv_proof_for_tx(tx_hash)
        self.qbusy = False

    def remove_spv_proof_for_tx(self, tx_hash):
        self.merkle_roots.pop(tx_hash, None)
        self.requested_merkle.discard(tx_hash)

    def is_up_to_date(self):
        return not self.requested_merkle
