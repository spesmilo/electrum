#!/usr/bin/env python
from json import loads, dumps
from sys import exit, argv
import base64
import urllib2

if len(argv) < 3:
    print('Arguments: <rpc_username> <rpc_password> [<rpc_port>]')
    sys.exit(1)

# From electrum.
def bits_to_target(bits):
    bitsN = (bits >> 24) & 0xff
    if not (bitsN >= 0x03 and bitsN <= 0x1e):
        raise BaseException("First part of bits should be in [0x03, 0x1e]")
    bitsBase = bits & 0xffffff
    if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
        raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
    return bitsBase << (8 * (bitsN-3))

def rpc(method, params):
    data = {
        "jsonrpc": "1.0",
        "id":"curltest",
        "method": method,
        "params": params
    }

    data_json = dumps(data)
    username = argv[1]
    password = argv[2]
    port = 1441
    if len(argv) > 3:
        port = argv[3]
    url = "http://127.0.0.1:{}/".format(port)
    req = urllib2.Request(url, data_json, {'content-type': 'application/json'})

    base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
    req.add_header("Authorization", "Basic %s" % base64string)

    response_stream = urllib2.urlopen(req)
    json_response = response_stream.read()

    return loads(json_response)

# Electrum-GRS checkpoints are blocks 2015, 2015 + 2016, 2015 + 2016*2, ...
i = 2015
INTERVAL = 2016

checkpoints = []
block_count = int(rpc('getblockcount', [])['result'])
print('Blocks: {}'.format(block_count))
while True:
    h = rpc('getblockhash', [i])['result']
    block = rpc('getblock', [h])['result']

    checkpoints.append([
        block['hash'],
        bits_to_target(int(block['bits'], 16))
    ])

    i += INTERVAL
    if i > block_count:
        print('Done.')
        break

with open('checkpoints_output.json', 'w+') as f:
    f.write(dumps(checkpoints, indent=4, separators=(',', ':')))
