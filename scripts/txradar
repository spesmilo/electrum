#!/usr/bin/env python3
import util, sys
try:
    tx = sys.argv[1]
except:
    print("usage: txradar txid")
    sys.exit(1)

peers = util.get_peers()
results = util.send_request(peers, 'blockchain.transaction.get', [tx])

r1 = []
r2 = []

for k, v in results.items():
    (r1 if v else r2).append(k)

print("Received %d answers"%len(results))
print("Propagation rate: %.1f percent" % (len(r1) *100./(len(r1)+ len(r2))))
