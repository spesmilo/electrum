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

from bitcoin import MIN_RELAY_TX_FEE
from util import NotEnoughFunds, PrintError, profiler
from transaction import Transaction


class CoinChooser(PrintError):
    def __init__(self, wallet):
        self.wallet = wallet

    def fee(self, tx, fixed_fee, fee_per_kb):
        if fixed_fee is not None:
            return fixed_fee
        return tx.estimated_fee(fee_per_kb)

    def dust_threshold(self):
        return 182 * 3 * MIN_RELAY_TX_FEE/1000

    def make_tx(self, coins, outputs, change_addrs, fixed_fee, fee_per_kb):
        '''Select unspent coins to spend to pay outputs.'''
        amount = sum(map(lambda x: x[2], outputs))
        total = 0
        inputs = []
        tx = Transaction.from_io(inputs, outputs)
        fee = self.fee(tx, fixed_fee, fee_per_kb)
        # add inputs, sorted by age
        for item in coins:
            v = item.get('value')
            total += v
            self.wallet.add_input_info(item)
            tx.add_input(item)
            # no need to estimate fee until we have reached desired amount
            if total < amount + fee:
                continue
            fee = self.fee(tx, fixed_fee, fee_per_kb)
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
            fee = self.fee(tx, fixed_fee, fee_per_kb)
            for item in sorted(tx.inputs, key=itemgetter('value')):
                v = item.get('value')
                if total - v >= amount + fee:
                    tx.inputs.remove(item)
                    total -= v
                    fee = self.fee(tx, fixed_fee, fee_per_kb)
                    continue
                break
        self.print_error("using %d inputs" % len(tx.inputs))

        # if change is above dust threshold, add a change output.
        change_addr = change_addrs[0]
        change_amount = total - (amount + fee)
        if fixed_fee is not None and change_amount > 0:
            tx.outputs.append(('address', change_addr, change_amount))
        elif change_amount > self.dust_threshold():
            tx.outputs.append(('address', change_addr, change_amount))
            # recompute fee including change output
            fee = tx.estimated_fee(fee_per_kb)
            # remove change output
            tx.outputs.pop()
            # if change is still above dust threshold, re-add change output.
            change_amount = total - (amount + fee)
            if change_amount > self.dust_threshold():
                tx.outputs.append(('address', change_addr, change_amount))
                self.print_error('change', change_amount)
            else:
                self.print_error('not keeping dust', change_amount)
        else:
            self.print_error('not keeping dust', change_amount)

        return tx
