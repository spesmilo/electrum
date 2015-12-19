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
from random import choice, randint, shuffle
from math import floor, log10

from bitcoin import COIN
from transaction import Transaction
from util import NotEnoughFunds, PrintError, profiler

Bucket = namedtuple('Bucket', ['desc', 'size', 'value', 'coins'])

def strip_unneeded(bkts, sufficient_funds):
    '''Remove buckets that are unnecessary in achieving the spend amount'''
    bkts = sorted(bkts, key = lambda bkt: bkt.value)
    for i in range(len(bkts)):
        if not sufficient_funds(bkts[i + 1:]):
            return bkts[i:]
    # Shouldn't get here
    return bkts

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

    def change_amounts(self, tx, count, fee_estimator, dust_threshold):
        # The amount left after adding 1 change output
        return [max(0, tx.get_fee() - fee_estimator(1))]

    def change_outputs(self, tx, change_addrs, fee_estimator, dust_threshold):
        amounts = self.change_amounts(tx, len(change_addrs), fee_estimator,
                                      dust_threshold)
        assert min(amounts) >= 0
        # If change is above dust threshold after accounting for the
        # size of the change output, add it to the transaction.
        dust = sum(amount for amount in amounts if amount < dust_threshold)
        amounts = [amount for amount in amounts if amount >= dust_threshold]
        change = [('address', addr, amount)
                  for addr, amount in zip(change_addrs, amounts)]
        self.print_error('change:', change)
        if dust:
            self.print_error('not keeping dust', dust)
        return change

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
        spent_amount = tx.output_value()

        def sufficient_funds(buckets):
            '''Given a list of buckets, return True if it has enough
            value to pay for the transaction'''
            total_input = sum(bucket.value for bucket in buckets)
            total_size = sum(bucket.size for bucket in buckets) + base_size
            return total_input >= spent_amount + fee_estimator(total_size)

        # Collect the coins into buckets, choose a subset of the buckets
        buckets = self.bucketize_coins(coins)
        buckets = self.choose_buckets(buckets, sufficient_funds,
                                      self.penalty_func(tx))

        tx.inputs = [coin for b in buckets for coin in b.coins]
        tx_size = base_size + sum(bucket.size for bucket in buckets)

        # This takes a count of change outputs and returns a tx fee;
        # each pay-to-bitcoin-address output serializes as 34 bytes
        fee = lambda count: fee_estimator(tx_size + count * 34)
        change = self.change_outputs(tx, change_addrs, fee, dust_threshold)
        tx.outputs.extend(change)

        self.print_error("using %d inputs" % len(tx.inputs))
        self.print_error("using buckets:", [bucket.desc for bucket in buckets])

        return tx

class CoinChooserOldestFirst(CoinChooserBase):
    '''The classic electrum algorithm.  Chooses coins starting with the
    oldest that are sufficient to cover the spent amount, and then
    removes any unneeded starting with the smallest in value.'''

    def keys(self, coins):
        return [coin['prevout_hash'] + ':' + str(coin['prevout_n'])
                for coin in coins]

    def choose_buckets(self, buckets, sufficient_funds, penalty_func):
        '''Spend the oldest buckets first.'''
        # Unconfirmed coins are young, not old
        adj_height = lambda height: 99999999 if height == 0 else height
        buckets.sort(key = lambda b: max(adj_height(coin['height'])
                                         for coin in b.coins))
        selected = []
        for bucket in buckets:
            selected.append(bucket)
            if sufficient_funds(selected):
                return strip_unneeded(selected, sufficient_funds)
        else:
            raise NotEnoughFunds()

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

        candidates = [[buckets[n] for n in c] for c in candidates]
        return [strip_unneeded(c, sufficient_funds) for c in candidates]

    def choose_buckets(self, buckets, sufficient_funds, penalty_func):
        candidates = self.bucket_candidates(buckets, sufficient_funds)
        penalties = [penalty_func(cand) for cand in candidates]
        winner = candidates[penalties.index(min(penalties))]
        self.print_error("Bucket sets:", len(buckets))
        self.print_error("Winning penalty:", min(penalties))
        return winner

class CoinChooserPrivacy(CoinChooserRandom):
    '''Attempts to better preserve user privacy.  First, if any coin is
    spent from a user address, all coins are.  Compared to spending
    from other addresses to make up an amount, this reduces
    information leakage about sender holdings.  It also helps to
    reduce blockchain UTXO bloat, and reduce future privacy loss that
    would come from reusing that address' remaining UTXOs.  Second, it
    penalizes change that is quite different to the sent amount.
    Third, it penalizes change that is too big. Fourth, it breaks
    large change up into amounts comparable to the spent amount.
    Finally, change is rounded to similar precision to sent amounts.
    Extra change outputs and rounding might raise the transaction fee
    slightly.  Transaction priority might be less than if older coins
    were chosen.'''

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

    def change_amounts(self, tx, count, fee_estimator, dust_threshold):

        # Break change up if bigger than max_change
        output_amounts = [o[2] for o in tx.outputs]
        max_change = max(max(output_amounts) * 1.25, dust_threshold * 10)

        # Use N change outputs
        for n in range(1, count + 1):
            # How much is left if we add this many change outputs?
            change_amount = max(0, tx.get_fee() - fee_estimator(n))
            if change_amount // n <= max_change:
                break

        # Get a handle on the precision of the output amounts; round our
        # change to look similar
        def trailing_zeroes(val):
            s = str(val)
            return len(s) - len(s.rstrip('0'))

        zeroes = map(trailing_zeroes, output_amounts)
        min_zeroes = min(zeroes)
        max_zeroes = max(zeroes)
        zeroes = range(max(0, min_zeroes - 1), (max_zeroes + 1) + 1)

        # Calculate change; randomize it a bit if using more than 1 output
        remaining = change_amount
        amounts = []
        while n > 1:
            average = remaining // n
            amount = randint(int(average * 0.7), int(average * 1.3))
            precision = min(choice(zeroes), int(floor(log10(amount))))
            amount = int(round(amount, -precision))
            amounts.append(amount)
            remaining -= amount
            n -= 1

        # Last change output.  Round down to maximum precision but lose
        # no more than 100 satoshis to fees (2dp)
        N = pow(10, min(2, zeroes[0]))
        amount = (remaining // N) * N
        amounts.append(amount)

        assert sum(amounts) <= change_amount

        return amounts


COIN_CHOOSERS = {'Oldest First': CoinChooserOldestFirst,
                 'Privacy': CoinChooserPrivacy}
