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

from .btchipException import *
from .bitcoinTransaction import *
from .btchipHelpers import *

def compress_public_key(publicKey):
	if publicKey[0] == 0x04:
		if (publicKey[64] & 1) != 0:
			prefix = 0x03
		else:
			prefix = 0x02
		result = [prefix]
		result.extend(publicKey[1:33])
		return bytearray(result)
	elif publicKey[0] == 0x03 or publicKey[0] == 0x02:
		return publicKey
	else:
		raise BTChipException("Invalid public key format")

def format_transaction(dongleOutputData, trustedInputsAndInputScripts, version=0x01, lockTime=0):
	transaction = bitcoinTransaction()
	transaction.version = []
	writeUint32LE(version, transaction.version)
	for item in trustedInputsAndInputScripts:
		newInput = bitcoinInput()
		newInput.prevOut = item[0][4:4+36]
		newInput.script = item[1]
		if len(item) > 2:
			newInput.sequence = bytearray(item[2].decode('hex'))
		else:
			newInput.sequence = bytearray([0xff, 0xff, 0xff, 0xff])
		transaction.inputs.append(newInput)
	result = transaction.serialize(True)
	result.extend(dongleOutputData)
	writeUint32LE(lockTime, result)
	return bytearray(result)

def get_regular_input_script(sigHashtype, publicKey):
	if len(sigHashtype) >= 0x4c:
		raise BTChipException("Invalid sigHashtype")
	if len(publicKey) >= 0x4c:
		raise BTChipException("Invalid publicKey")
	result = [ len(sigHashtype) ]
	result.extend(sigHashtype)
	result.append(len(publicKey))
	result.extend(publicKey)
	return bytearray(result)

def write_pushed_data_size(data, buffer):
	if (len(data) > 0xffff):
		raise BTChipException("unsupported encoding")
	if (len(data) < 0x4c):
		buffer.append(len(data))
	elif (len(data) > 255):
		buffer.append(0x4d)
		buffer.append(len(data) & 0xff)
		buffer.append((len(data) >> 8) & 0xff)
	else:
		buffer.append(0x4c)
		buffer.append(len(data))
	return buffer


def get_p2sh_input_script(redeemScript, sigHashtypeList):
	result = [ 0x00 ]
	for sigHashtype in sigHashtypeList:
		write_pushed_data_size(sigHashtype, result)
		result.extend(sigHashtype)
	write_pushed_data_size(redeemScript, result)
	result.extend(redeemScript)
	return bytearray(result)

def get_p2pk_input_script(sigHashtype):
	if len(sigHashtype) >= 0x4c:
		raise BTChipException("Invalid sigHashtype")
	result = [ len(sigHashtype) ]
	result.extend(sigHashtype)
	return bytearray(result)

def get_output_script(amountScriptArray):
	result = [ len(amountScriptArray) ]
	for amountScript in amountScriptArray:
		writeHexAmount(btc_to_satoshi(str(amountScript[0])), result)
		writeVarint(len(amountScript[1]), result)
		result.extend(amountScript[1])
	return bytearray(result)

