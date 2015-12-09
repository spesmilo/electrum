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

from collections import defaultdict, namedtuple
from random import shuffle

from bitcoin import COIN
from transaction import Transaction
from util import NotEnoughFunds, PrintError, profiler

Bucket = namedtuple('Bucket', ['desc', 'size', 'value', 'coins'])

class CoinChooserBase(PrintError):

    def keys(self, coins):
        raise NotImplementedError

    def bucketize_coins(self, coins):
        keys = self.keys(coins)
        buckets = defaultdict(list)
        for key, coin in zip(keys, coins):
            buckets[key].append(coin)

        def make_Bucket(desc, coins):
            size = sum(Transaction.estimated_input_size(coin)
                       for coin in coins)
            value = sum(coin['value'] for coin in coins)
            return Bucket(desc, size, value, coins)

        return map(make_Bucket, buckets.keys(), buckets.values())

    def penalty_func(self, tx):
        def penalty(candidate):
            return 0
        return penalty

    def add_change(self, tx, change_addrs, fee_estimator, dust_threshold):
        # How much is left if we add 1 change output?
        change_amount = tx.get_fee() - fee_estimator(1)

        # If change is above dust threshold after accounting for the
        # size of the change output, add it to the transaction.
        if change_amount > dust_threshold:
            tx.outputs.append(('address', change_addrs[0], change_amount))
            self.print_error('change', change_amount)
        elif change_amount:
            self.print_error('not keeping dust', change_amount)

    def make_tx(self, coins, outputs, change_addrs, fee_estimator,
                dust_threshold):
        '''Select unspent coins to spend to pay outputs.  If the change is
        greater than dust_threshold (after adding the change output to
        the transaction) it is kept, otherwise none is sent and it is
        added to the transaction fee.'''

        # Copy the ouputs so when adding change we don't modify "outputs"
        tx = Transaction.from_io([], outputs[:])
        # Size of the transaction with no inputs and no change
        base_size = tx.estimated_size()
        # Returns fee given input size
        fee = lambda input_size: fee_estimator(base_size + input_size)

        # Collect the coins into buckets, choose a subset of the buckets
        buckets = self.bucketize_coins(coins)
        buckets = self.choose_buckets(buckets, tx.output_value(), fee,
                                      self.penalty_func(tx))

        tx.inputs = [coin for b in buckets for coin in b.coins]
        tx_size = base_size + sum(bucket.size for bucket in buckets)

        # This takes a count of change outputs and returns a tx fee;
        # each pay-to-bitcoin-address output serializes as 34 bytes
        fee = lambda count: fee_estimator(tx_size + count * 34)
        self.add_change(tx, change_addrs, fee, dust_threshold)

        self.print_error("using %d inputs" % len(tx.inputs))
        self.print_error("using buckets:", [bucket.desc for bucket in buckets])

        return tx

class CoinChooserClassic(CoinChooserBase):
    '''
    The classic electrum algorithm.  Chooses coins starting with
    the oldest that are sufficient to cover the spent amount, and
    then removes any unneeded starting with the smallest in value.'''

    def keys(self, coins):
        return [coin['prevout_hash'] + ':' + str(coin['prevout_n'])
                for coin in coins]

    def choose_buckets(self, buckets, spent_amount, fee, penalty_func):
        '''Spend the oldest buckets first.'''
        # Unconfirmed coins are young, not old
        adj_height = lambda height: 99999999 if height == 0 else height
        buckets.sort(key = lambda b: max(adj_height(coin['height'])
                                         for coin in b.coins))
        selected, value, size = [], 0, 0
        for bucket in buckets:
            selected.append(bucket)
            value += bucket.value
            size += bucket.size
            if value >= spent_amount + fee(size):
                break
        else:
            raise NotEnoughFunds()

        # Remove unneeded inputs starting with the smallest.
        selected.sort(key = lambda b: b.value)
        dropped = []
        for bucket in selected:
            if value - bucket.value >= spent_amount + fee(size - bucket.size):
                value -= bucket.value
                size -= bucket.size
                dropped.append(bucket)

        return [bucket for bucket in selected if bucket not in dropped]

class CoinChooserRandom(CoinChooserBase):

    def bucket_candidates(self, buckets, sufficient_funds):
        '''Returns a list of bucket sets.'''
        candidates = set()

        # Add all singletons
        for n, bucket in enumerate(buckets):
            if sufficient_funds([bucket]):
                candidates.add((n, ))

        # And now some random ones
        attempts = min(100, (len(buckets) - 1) * 10 + 1)
        permutation = range(len(buckets))
        for i in range(attempts):
            # Get a random permutation of the buckets, and
            # incrementally combine buckets until sufficient
            shuffle(permutation)
            bkts = []
            for count, index in enumerate(permutation):
                bkts.append(buckets[index])
                if sufficient_funds(bkts):
                    candidates.add(tuple(sorted(permutation[:count + 1])))
                    break
            else:
                raise NotEnoughFunds()

        return [[buckets[n] for n in candidate] for candidate in candidates]

    def choose_buckets(self, buckets, spent_amount, fee, penalty_func):

        def sufficient(buckets):
            '''Given a set of buckets, return True if it has enough
            value to pay for the transaction'''
            total_input = sum(bucket.value for bucket in buckets)
            total_size = sum(bucket.size for bucket in buckets)
            return total_input >= spent_amount + fee(total_size)

        candidates = self.bucket_candidates(buckets, sufficient)
        penalties = [penalty_func(cand) for cand in candidates]
        winner = candidates[penalties.index(min(penalties))]
        self.print_error("Bucket sets:", len(buckets))
        self.print_error("Winning penalty:", min(penalties))
        return winner

class CoinChooserPrivacy(CoinChooserRandom):
    '''
    Attempts to better preserve user privacy.  First, if any coin is
    spent from a user address, all coins are.  Compared to spending
    from other addresses to make up an amount, this reduces
    information leakage about sender holdings.  It also helps to
    reduce blockchain UTXO bloat, and reduce future privacy loss
    that would come from reusing that address' remaining UTXOs.
    Second, it penalizes change that is quite different to the sent
    amount.  Third, it penalizes change that is too big.'''

    def keys(self, coins):
        return [coin['address'] for coin in coins]

    def penalty_func(self, buckets, tx):
        '''Returns a penalty for a candidate set of buckets.'''
        raise NotImplementedError

    def penalty_func(self, tx):
        min_change = min(o[2] for o in tx.outputs) * 0.75
        max_change = max(o[2] for o in tx.outputs) * 1.33
        spent_amount = sum(o[2] for o in tx.outputs)

        def penalty(buckets):
            badness = len(buckets) - 1
            total_input = sum(bucket.value for bucket in buckets)
            change = float(total_input - spent_amount)
            # Penalize change not roughly in output range
            if change < min_change:
                badness += (min_change - change) / (min_change + 10000)
            elif change > max_change:
                badness += (change - max_change) / (max_change + 10000)
                # Penalize large change; 5 BTC excess ~= using 1 more input
                badness += change / (COIN * 5)
            return badness

        return penalty

COIN_CHOOSERS = {'Classic': CoinChooserClassic,
                 'Privacy': CoinChooserPrivacy}
