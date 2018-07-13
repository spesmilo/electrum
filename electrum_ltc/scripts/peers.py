#!/usr/bin/env python3

from . import util

from electrum_ltc.network import filter_protocol
from electrum_ltc.blockchain import hash_header

peers = util.get_peers()
peers = filter_protocol(peers, 's')

results = util.send_request(peers, 'blockchain.headers.subscribe', [])

for n,v in sorted(results.items(), key=lambda x:x[1].get('block_height')):
    print("%60s"%n, v.get('block_height'), hash_header(v))
