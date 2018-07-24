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

from typing import Sequence, Optional

from .util import ThreadJob, bh2u
from .bitcoin import Hash, hash_decode, hash_encode
from .transaction import Transaction


class MerkleVerificationFailure(Exception): pass
class MissingBlockHeader(MerkleVerificationFailure): pass
class MerkleRootMismatch(MerkleVerificationFailure): pass
class InnerNodeOfSpvProofIsValidTx(MerkleVerificationFailure): pass


class SPV(ThreadJob):
    """ Simple Payment Verification """

    def __init__(self, network, wallet):
        self.wallet = wallet
        self.network = network
        self.blockchain = network.blockchain()
        self.merkle_roots = {}  # txid -> merkle root (once it has been verified)
        self.requested_merkle = set()  # txid set of pending requests

    def run(self):
        interface = self.network.interface
        if not interface:
            return

        blockchain = interface.blockchain
        if not blockchain:
            return

        local_height = self.network.get_local_height()
        unverified = self.wallet.get_unverified_txs()
        for tx_hash, tx_height in unverified.items():
            # do not request merkle branch before headers are available
            if tx_height <= 0 or tx_height > local_height:
                continue

            header = blockchain.read_header(tx_height)
            if header is None:
                index = tx_height // 2016
                if index < len(blockchain.checkpoints):
                    self.network.request_chunk(interface, index)
            elif (tx_hash not in self.requested_merkle
                    and tx_hash not in self.merkle_roots):
                self.network.get_merkle_for_transaction(
                        tx_hash,
                        tx_height,
                        self.verify_merkle)
                self.print_error('requested merkle', tx_hash)
                self.requested_merkle.add(tx_hash)

        if self.network.blockchain() != self.blockchain:
            self.blockchain = self.network.blockchain()
            self.undo_verifications()

    def verify_merkle(self, response):
        if self.wallet.verifier is None:
            return  # we have been killed, this was just an orphan callback
        if response.get('error'):
            self.print_error('received an error:', response)
            return
        params = response['params']
        merkle = response['result']
        # Verify the hash of the server-provided merkle branch to a
        # transaction matches the merkle root of its block
        tx_hash = params[0]
        tx_height = merkle.get('block_height')
        pos = merkle.get('pos')
        merkle_branch = merkle.get('merkle')
        header = self.network.blockchain().read_header(tx_height)
        try:
            verify_tx_is_in_block(tx_hash, merkle_branch, pos, header, tx_height)
        except MerkleVerificationFailure as e:
            self.print_error(str(e))
            # FIXME: we should make a fresh connection to a server
            # to recover from this, as this TX will now never verify
            return
        # we passed all the tests
        self.merkle_roots[tx_hash] = header.get('merkle_root')
        try:
            # note: we could pop in the beginning, but then we would request
            # this proof again in case of verification failure from the same server
            self.requested_merkle.remove(tx_hash)
        except KeyError: pass
        self.print_error("verified %s" % tx_hash)
        self.wallet.add_verified_tx(tx_hash, (tx_height, header.get('timestamp'), pos))
        if self.is_up_to_date() and self.wallet.is_up_to_date():
            self.wallet.save_verified_tx(write=True)

    @classmethod
    def hash_merkle_root(cls, merkle_branch: Sequence[str], tx_hash: str, leaf_pos_in_tree: int):
        """Return calculated merkle root."""
        try:
            h = hash_decode(tx_hash)
            merkle_branch_bytes = [hash_decode(item) for item in merkle_branch]
            int(leaf_pos_in_tree)  # raise if invalid
        except Exception as e:
            raise MerkleVerificationFailure(e)

        for i, item in enumerate(merkle_branch_bytes):
            h = Hash(item + h) if ((leaf_pos_in_tree >> i) & 1) else Hash(h + item)
            cls._raise_if_valid_tx(bh2u(h))
        return hash_encode(h)

    @classmethod
    def _raise_if_valid_tx(cls, raw_tx: str):
        # If an inner node of the merkle proof is also a valid tx, chances are, this is an attack.
        # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-June/016105.html
        # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20180609/9f4f5b1f/attachment-0001.pdf
        # https://bitcoin.stackexchange.com/questions/76121/how-is-the-leaf-node-weakness-in-merkle-trees-exploitable/76122#76122
        tx = Transaction(raw_tx)
        try:
            tx.deserialize()
        except:
            pass
        else:
            raise InnerNodeOfSpvProofIsValidTx()

    def undo_verifications(self):
        height = self.blockchain.get_checkpoint()
        tx_hashes = self.wallet.undo_verifications(self.blockchain, height)
        for tx_hash in tx_hashes:
            self.print_error("redoing", tx_hash)
            self.remove_spv_proof_for_tx(tx_hash)

    def remove_spv_proof_for_tx(self, tx_hash):
        self.merkle_roots.pop(tx_hash, None)
        try:
            self.requested_merkle.remove(tx_hash)
        except KeyError:
            pass

    def is_up_to_date(self):
        return not self.requested_merkle


def verify_tx_is_in_block(tx_hash: str, merkle_branch: Sequence[str],
                          leaf_pos_in_tree: int, block_header: Optional[dict],
                          block_height: int) -> None:
    """Raise MerkleVerificationFailure if verification fails."""
    if not block_header:
        raise MissingBlockHeader("merkle verification failed for {} (missing header {})"
                                 .format(tx_hash, block_height))
    calc_merkle_root = SPV.hash_merkle_root(merkle_branch, tx_hash, leaf_pos_in_tree)
    if block_header.get('merkle_root') != calc_merkle_root:
        raise MerkleRootMismatch("merkle verification failed for {} ({} != {})".format(
            tx_hash, block_header.get('merkle_root'), calc_merkle_root))
