#!/usr/bin/env python3

# A simple script that connects to a server and displays block headers

import time
from .. import SimpleConfig, Network
from electrum_ltc.util import print_msg, json_encode

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
network.send([('server.version',["block_headers script", "1.2"])], callback)
network.subscribe_to_headers(callback)

# 3. wait for results
while network.is_connected():
    time.sleep(1)
