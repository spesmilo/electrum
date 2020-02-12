"""
*******************************************************************************
*   BTChip Bitcoin Hardware Wallet Python API
*   (c) 2014 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************
"""

import decimal
import re

# from pycoin
SATOSHI_PER_COIN = decimal.Decimal(1e8)
COIN_PER_SATOSHI = decimal.Decimal(1)/SATOSHI_PER_COIN

def satoshi_to_btc(satoshi_count):
    if satoshi_count == 0:
        return decimal.Decimal(0)
    r = satoshi_count * COIN_PER_SATOSHI
    return r.normalize()

def btc_to_satoshi(btc):
    return int(decimal.Decimal(btc) * SATOSHI_PER_COIN)
# /from pycoin

def writeUint32BE(value, buffer):
	buffer.append((value >> 24) & 0xff)
	buffer.append((value >> 16) & 0xff)
	buffer.append((value >> 8) & 0xff)
	buffer.append(value & 0xff)
	return buffer

def writeUint32LE(value, buffer):
	buffer.append(value & 0xff)
	buffer.append((value >> 8) & 0xff)
	buffer.append((value >> 16) & 0xff)
	buffer.append((value >> 24) & 0xff)
	return buffer

def writeHexAmount(value, buffer):
	buffer.append(value & 0xff)
	buffer.append((value >> 8) & 0xff)
	buffer.append((value >> 16) & 0xff)
	buffer.append((value >> 24) & 0xff)
	buffer.append((value >> 32) & 0xff)
	buffer.append((value >> 40) & 0xff)
	buffer.append((value >> 48) & 0xff)
	buffer.append((value >> 56) & 0xff)
	return buffer

def writeHexAmountBE(value, buffer):
	buffer.append((value >> 56) & 0xff)
	buffer.append((value >> 48) & 0xff)
	buffer.append((value >> 40) & 0xff)
	buffer.append((value >> 32) & 0xff)
	buffer.append((value >> 24) & 0xff)
	buffer.append((value >> 16) & 0xff)
	buffer.append((value >> 8) & 0xff)
	buffer.append(value & 0xff)
	return buffer

def parse_bip32_path(path):
	if len(path) == 0:
		return bytearray([ 0 ])
	result = []
	elements = path.split('/')
	if len(elements) > 10:
		raise BTChipException("Path too long")
	for pathElement in elements:
		element = re.split('\'|h|H', pathElement)
		if len(element) == 1:
			writeUint32BE(int(element[0]), result)
		else:
			writeUint32BE(0x80000000 | int(element[0]), result)
	return bytearray([ len(elements) ] + result)
