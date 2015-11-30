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

from util import NotEnoughFunds, PrintError, profiler
from transaction import Transaction

Bucket = namedtuple('Bucket', ['desc', 'size', 'value', 'coins'])

class CoinChooserBase(PrintError):

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

    def make_tx(self, coins, outputs, change_addrs, fee_estimator,
                dust_threshold):
        '''Select unspent coins to spend to pay outputs.  If the change is
        greater than dust_threshold (after adding the change output to
        the transaction) it is kept, otherwise none is sent and it is
        added to the transaction fee.'''
        output_total = sum(map(lambda x: x[2], outputs))

        # Size of the transaction with no inputs and no change
        tx = Transaction.from_io([], outputs)
        base_size = tx.estimated_size()
        # Returns fee given input size
        fee = lambda input_size: fee_estimator(base_size + input_size)

        # Collect the coins into buckets, choose a subset of the buckets
        buckets = self.bucketize_coins(coins)
        buckets = self.choose_buckets(buckets, output_total, fee)

        tx.inputs = [coin for b in buckets for coin in b.coins]
        input_total = sum(bucket.value for bucket in buckets)
        tx_size = base_size + sum(bucket.size for bucket in buckets)

        # If change is above dust threshold after accounting for the
        # size of the change output, add it to the transaction.
        # Pay to bitcoin address serializes as 34 bytes
        change_size = 34
        fee = fee_estimator(tx_size + change_size)
        change_amount = input_total - (output_total + fee)
        if change_amount > dust_threshold:
            tx.outputs.append(('address', change_addrs[0], change_amount))
            self.print_error('change', change_amount)
        elif change_amount:
            self.print_error('not keeping dust', change_amount)

        self.print_error("using %d inputs" % len(tx.inputs))
        self.print_error("using buckets:", [bucket.desc for bucket in buckets])

        return tx

class CoinChooser(CoinChooserBase):
    '''The original electrum algorithm.  Chooses coins starting with the
    oldest that are sufficient to cover the spent amount, and then
    removes any not needed starting with the smallest in value.'''

    def keys(self, coins):
        return [coin['prevout_hash'] + ':' + str(coin['prevout_n'])
                for coin in coins]

    def choose_buckets(self, buckets, spent_amount, fee):
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
