#!/usr/bin/env python
from json import loads, dumps
from sys import exit, argv
import base64
import urllib.request

from slickrpc import Proxy
bitcoin = Proxy("http://%s:%s@127.0.0.1:44444"%("user","password"))

# Electrum checkpoints are blocks 2015, 2015 + 2016, 2015 + 2016*2, ...
i = 2015
INTERVAL = 2016

# From electrum.
def bits_to_target(bits):
    bitsN = (bits >> 24) & 0xff
    if not (bitsN >= 0x03 and bitsN <= 0x1e):
        raise BaseException("First part of bits should be in [0x03, 0x1e]")
    bitsBase = bits & 0xffffff
    if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
        raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
    return bitsBase << (8 * (bitsN-3))


checkpoints = []
block_count = bitcoin.getblockcount()

print('Blocks: {}'.format(block_count))
while True:
    block = bitcoin.getblock(bitcoin.getblockhash(i))

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
