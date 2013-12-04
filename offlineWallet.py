#!/usr/bin/env python2
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 the9ull@github
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
#

'''\
offlineWallet is a utility to create an Electrum wallet on a offline computer.
It requires ecdsa and slowaes Python library installed

 USAGE: ./offlineWallet.py [gap-limit]\
'''

# Dependencies:
#  - https://pypi.python.org/pypi/ecdsa
#  - https://pypi.python.org/pypi/slowaes

import sys

from lib.wallet import WalletStorage, Wallet
from lib.simple_config import SimpleConfig

offline_config = {
    "portable":True,
    "verbose":False,
    "auto_cycle":True,
    "wallet_path":"will/never/exist/file",
}

class EphemeralStorage(WalletStorage):
    '''
    Don't create wallet file
    '''
    def write(self):
        pass

if __name__=="__main__":

    # options
    if sys.argv[1:]:
        if sys.argv[1] in ['-h','--help','-?']:
            print __doc__
            sys.exit(0)
        gap_limit = int(sys.argv[1]) if int(sys.argv[1]) >= 5 else 5
    else:
        gap_limit = 10

    config = SimpleConfig(offline_config)
    storage = EphemeralStorage(config)
    storage.write = lambda : None
    wallet = Wallet(storage)
    wallet.init_seed(None)
    #wallet.save_seed()
    wallet.create_accounts() #called by save_seed
    wallet.change_gap_limit(gap_limit)
    wallet.synchronize()

    
    print
    print
    print 'SEED',wallet.get_mnemonic(None)

    for a,k in [(address,wallet.get_private_key(address, None)[0]) for address in wallet.addresses(False)]:
        print a,k
