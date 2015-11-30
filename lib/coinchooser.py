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
        inputs = []
        tx = Transaction.from_io(inputs, outputs)
        fee = fee_estimator(tx)
        # add inputs, sorted by age
        for item in coins:
            v = item.get('value')
            total += v
            tx.add_input(item)
            # no need to estimate fee until we have reached desired amount
            if total < amount + fee:
                continue
            fee = fee_estimator(tx)
            if total >= amount + fee:
                break
        else:
            raise NotEnoughFunds()

        # remove unneeded inputs.
        removed = False
        for item in sorted(tx.inputs, key=itemgetter('value')):
            v = item.get('value')
            if total - v >= amount + fee:
                tx.inputs.remove(item)
                total -= v
                removed = True
                continue
            else:
                break
        if removed:
            fee = fee_estimator(tx)
            for item in sorted(tx.inputs, key=itemgetter('value')):
                v = item.get('value')
                if total - v >= amount + fee:
                    tx.inputs.remove(item)
                    total -= v
                    fee = fee_estimator(tx)
                    continue
                break
        self.print_error("using %d inputs" % len(tx.inputs))

        # if change is above dust threshold, add a change output.
        change_addr = change_addrs[0]
        change_amount = total - (amount + fee)

        # See if change would still be greater than dust after adding
        # the change to the transaction
        if change_amount > dust_threshold:
            tx.outputs.append(('address', change_addr, change_amount))
            fee = fee_estimator(tx)
            # remove change output
            tx.outputs.pop()
            change_amount = total - (amount + fee)

        # If change is still above dust threshold, keep the change.
        if change_amount > dust_threshold:
            tx.outputs.append(('address', change_addr, change_amount))
            self.print_error('change', change_amount)
        elif change_amount:
            self.print_error('not keeping dust', change_amount)

        return tx
