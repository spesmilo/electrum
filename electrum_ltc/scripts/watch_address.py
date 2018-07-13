#!/usr/bin/env python3

import sys
import time
from electrum_ltc import bitcoin
from .. import SimpleConfig, Network
from electrum_ltc.util import print_msg, json_encode

try:
    addr = sys.argv[1]
except Exception:
    print("usage: watch_address <litecoin_address>")
    sys.exit(1)

sh = bitcoin.address_to_scripthash(addr)

# start network
c = SimpleConfig()
network = Network(c)
network.start()

# wait until connected
while network.is_connecting():
    time.sleep(0.1)

if not network.is_connected():
    print_msg("daemon is not connected")
    sys.exit(1)

# 2. send the subscription
callback = lambda response: print_msg(json_encode(response.get('result')))
network.subscribe_to_address(addr, callback)

# 3. wait for results
while network.is_connected():
    time.sleep(1)
