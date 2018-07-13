#!/usr/bin/env python3
from . import util
import json
from electrum_ltc.network import filter_protocol
peers = filter_protocol(util.get_peers())
results = util.send_request(peers, 'blockchain.estimatefee', [2])
print(json.dumps(results, indent=4))
