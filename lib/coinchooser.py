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

from operator import itemgetter

from util import NotEnoughFunds, PrintError, profiler
from transaction import Transaction


class CoinChooser(PrintError):

    def make_tx(self, coins, outputs, change_addrs, fee_estimator,
                dust_threshold):
        '''Select unspent coins to spend to pay outputs.  If the change is
        greater than dust_threshold (after adding the change output to
        the transaction) it is kept, otherwise none is sent and it is
        added to the transaction fee.'''
        amount = sum(map(lambda x: x[2], outputs))
        total = 0
        tx = Transaction.from_io([], outputs)

        # Size of the transaction with no inputs and no change
        base_size = tx.estimated_size()
        # Pay to bitcoin address serializes as 34 bytes
        change_size = 34
        # Size of each serialized coin
        for coin in coins:
            coin['size'] = Transaction.estimated_input_size(coin)

        size = base_size
        # add inputs, sorted by age
        for item in coins:
            v = item.get('value')
            total += v
            size += item['size']
            tx.add_input(item)
            if total >= amount + fee_estimator(size):
                break
        else:
            raise NotEnoughFunds()

        # remove unneeded inputs.
        for item in sorted(tx.inputs, key=itemgetter('value')):
            v = item.get('value')
            if total - v >= amount + fee_estimator(size - item['size']):
                tx.inputs.remove(item)
                total -= v
                size -= item['size']
        self.print_error("using %d inputs" % len(tx.inputs))

        # If change is above dust threshold after accounting for the
        # size of the change output, add it to the transaction.
        change_amount = total - (amount + fee_estimator(size + change_size))
        if change_amount > dust_threshold:
            tx.outputs.append(('address', change_addrs[0], change_amount))
            size += change_size
            self.print_error('change', change_amount)
        elif change_amount:
            self.print_error('not keeping dust', change_amount)

        return tx
