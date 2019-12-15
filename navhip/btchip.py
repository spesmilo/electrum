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

from .btchipComm import *
from .bitcoinTransaction import *
from .bitcoinVarint import *
from .btchipException import *
from .btchipHelpers import *
from .btchipKeyRecovery import *
from binascii import hexlify, unhexlify

class btchip:
	BTCHIP_CLA = 0xe0
	BTCHIP_JC_EXT_CLA = 0xf0

	BTCHIP_INS_SET_ALTERNATE_COIN_VERSION = 0x14
	BTCHIP_INS_SETUP = 0x20
	BTCHIP_INS_VERIFY_PIN = 0x22
	BTCHIP_INS_GET_OPERATION_MODE = 0x24
	BTCHIP_INS_SET_OPERATION_MODE = 0x26
	BTCHIP_INS_SET_KEYMAP = 0x28
	BTCHIP_INS_SET_COMM_PROTOCOL = 0x2a
	BTCHIP_INS_GET_WALLET_PUBLIC_KEY = 0x40
	BTCHIP_INS_GET_TRUSTED_INPUT = 0x42
	BTCHIP_INS_HASH_INPUT_START = 0x44
	BTCHIP_INS_HASH_INPUT_FINALIZE = 0x46
	BTCHIP_INS_HASH_SIGN = 0x48
	BTCHIP_INS_HASH_INPUT_FINALIZE_FULL = 0x4a
	BTCHIP_INS_GET_INTERNAL_CHAIN_INDEX = 0x4c
	BTCHIP_INS_SIGN_MESSAGE = 0x4e
	BTCHIP_INS_GET_TRANSACTION_LIMIT = 0xa0
	BTCHIP_INS_SET_TRANSACTION_LIMIT = 0xa2
	BTCHIP_INS_IMPORT_PRIVATE_KEY = 0xb0
	BTCHIP_INS_GET_PUBLIC_KEY = 0xb2
	BTCHIP_INS_DERIVE_BIP32_KEY = 0xb4
	BTCHIP_INS_SIGNVERIFY_IMMEDIATE = 0xb6
	BTCHIP_INS_GET_RANDOM = 0xc0
	BTCHIP_INS_GET_ATTESTATION = 0xc2
	BTCHIP_INS_GET_FIRMWARE_VERSION = 0xc4
	BTCHIP_INS_COMPOSE_MOFN_ADDRESS = 0xc6
	BTCHIP_INS_GET_POS_SEED = 0xca

	BTCHIP_INS_EXT_GET_HALF_PUBLIC_KEY = 0x20
	BTCHIP_INS_EXT_CACHE_PUT_PUBLIC_KEY = 0x22
	BTCHIP_INS_EXT_CACHE_HAS_PUBLIC_KEY = 0x24
	BTCHIP_INS_EXT_CACHE_GET_FEATURES = 0x26

	OPERATION_MODE_WALLET = 0x01
	OPERATION_MODE_RELAXED_WALLET = 0x02
	OPERATION_MODE_SERVER = 0x04
	OPERATION_MODE_DEVELOPER = 0x08

	FEATURE_UNCOMPRESSED_KEYS = 0x01
	FEATURE_RFC6979 = 0x02
	FEATURE_FREE_SIGHASHTYPE = 0x04
	FEATURE_NO_2FA_P2SH = 0x08

	QWERTY_KEYMAP = bytearray(unhexlify("000000000000000000000000760f00d4ffffffc7000000782c1e3420212224342627252e362d3738271e1f202122232425263333362e37381f0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d2f3130232d350405060708090a0b0c0d0e0f101112131415161718191a1b1c1d2f313035"))
	QWERTZ_KEYMAP = bytearray(unhexlify("000000000000000000000000760f00d4ffffffc7000000782c1e3420212224342627252e362d3738271e1f202122232425263333362e37381f0405060708090a0b0c0d0e0f101112131415161718191a1b1d1c2f3130232d350405060708090a0b0c0d0e0f101112131415161718191a1b1d1c2f313035"))
	AZERTY_KEYMAP = bytearray(unhexlify("08000000010000200100007820c8ffc3feffff07000000002c38202030341e21222d352e102e3637271e1f202122232425263736362e37101f1405060708090a0b0c0d0e0f331112130415161718191d1b1c1a2f64302f2d351405060708090a0b0c0d0e0f331112130415161718191d1b1c1a2f643035"))

	def __init__(self, dongle):
		self.dongle = dongle
		self.needKeyCache = False
		try:
			firmware = self.getFirmwareVersion()['version']
			self.multiOutputSupported = tuple(map(int, (firmware.split(".")))) >= (1, 1, 4)
			if self.multiOutputSupported:
				self.scriptBlockLength = 50
			else:
				self.scriptBlockLength = 255
		except:
			pass
		try:
			result = self.getJCExtendedFeatures()
			self.needKeyCache = (result['proprietaryApi'] == False)
		except:
			pass

	def setAlternateCoinVersion(self, versionRegular, versionP2SH):
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SET_ALTERNATE_COIN_VERSION, 0x00, 0x00, 0x02, versionRegular, versionP2SH]
		self.dongle.exchange(bytearray(apdu))

	def verifyPin(self, pin):
		if isinstance(pin, str):
			pin = pin.encode('utf-8')
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_VERIFY_PIN, 0x00, 0x00, len(pin) ]
		apdu.extend(bytearray(pin))
		self.dongle.exchange(bytearray(apdu))

	def getVerifyPinRemainingAttempts(self):
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_VERIFY_PIN, 0x80, 0x00, 0x01 ]
		apdu.extend(bytearray(b'0'))
		try:
			self.dongle.exchange(bytearray(apdu))
		except BTChipException as e:
			if ((e.sw & 0xfff0) == 0x63c0):
				return e.sw - 0x63c0
			raise e

	def getWalletPublicKey(self, path, showOnScreen=False, segwit=False, segwitNative=False, cashAddr=False):
		result = {}
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_WALLET_PUBLIC_KEY, 0x01 if showOnScreen else 0x00, 0x03 if cashAddr else 0x02 if segwitNative else 0x01 if segwit else 0x00, len(donglePath) ]
		apdu.extend(donglePath)
		response = self.dongle.exchange(bytearray(apdu))
		offset = 0
		result['publicKey'] = response[offset + 1 : offset + 1 + response[offset]]
		offset = offset + 1 + response[offset]
		result['address'] = str(response[offset + 1 : offset + 1 + response[offset]])
		offset = offset + 1 + response[offset]
		result['chainCode'] = response[offset : offset + 32]
		return result

	def getTrustedInput(self, transaction, index):
		result = {}
		# Header
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x00, 0x00 ]
		params = bytearray.fromhex("%.8x" % (index))
		params.extend(transaction.version)
		params.extend(transaction.time)
		writeVarint(len(transaction.inputs), params)
		apdu.append(len(params))
		apdu.extend(params)
		self.dongle.exchange(bytearray(apdu))
		# Each input
		for trinput in transaction.inputs:
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
			params = bytearray(trinput.prevOut)
			writeVarint(len(trinput.script), params)
			apdu.append(len(params))
			apdu.extend(params)
			self.dongle.exchange(bytearray(apdu))
			offset = 0
			while True:
				blockLength = 251
				if ((offset + blockLength) < len(trinput.script)):
					dataLength = blockLength
				else:
					dataLength = len(trinput.script) - offset
				params = bytearray(trinput.script[offset : offset + dataLength])
				if ((offset + dataLength) == len(trinput.script)):
					params.extend(trinput.sequence)
				apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, len(params) ]
				apdu.extend(params)
				self.dongle.exchange(bytearray(apdu))
				offset += dataLength
				if (offset >= len(trinput.script)):
					break
		# Number of outputs
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
		params = []
		writeVarint(len(transaction.outputs), params)
		apdu.append(len(params))
		apdu.extend(params)
		self.dongle.exchange(bytearray(apdu))
		# Each output
		indexOutput = 0
		for troutput in transaction.outputs:
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
			params = bytearray(troutput.amount)
			writeVarint(len(troutput.script), params)
			apdu.append(len(params))
			apdu.extend(params)
			self.dongle.exchange(bytearray(apdu))
			offset = 0
			while (offset < len(troutput.script)):
				blockLength = 255
				if ((offset + blockLength) < len(troutput.script)):
					dataLength = blockLength
				else:
					dataLength = len(troutput.script) - offset
				apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, dataLength ]
				apdu.extend(troutput.script[offset : offset + dataLength])
				self.dongle.exchange(bytearray(apdu))
				offset += dataLength

		# Locktime
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]

		strdzeelSerialized = []
		writeVarint(len(transaction.strdzeel), strdzeelSerialized)

		strdzeelSerialized.extend(transaction.strdzeel)

		params = [ ]
		params.extend(transaction.lockTime)

		writeVarint(len(strdzeelSerialized), params)
		apdu.append(len(params))
		apdu.extend(params)
		response = self.dongle.exchange(bytearray(apdu))

		offset = 0

		while (offset < len(strdzeelSerialized)):
			blockLength = 255
			if ((offset + blockLength) < len(strdzeelSerialized)):
				dataLength = blockLength
			else:
				dataLength = len(strdzeelSerialized) - offset
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, dataLength ]
			apdu.extend(strdzeelSerialized[offset : offset + dataLength])
			response = self.dongle.exchange(bytearray(apdu))
			offset += dataLength

		result['trustedInput'] = True
		result['value'] = response
		return result

	def startUntrustedTransaction(self, newTransaction, inputIndex, outputList, redeemScript, version=0x01, time=0x00, cashAddr=False):
		# Start building a fake transaction with the passed inputs
		segwit = False
		if newTransaction:
			for passedOutput in outputList:
				if ('witness' in passedOutput) and passedOutput['witness']:
					segwit = True
					break
		if newTransaction:
			if segwit:
				p2 = 0x03 if cashAddr else 0x02
			else:
				p2 = 0x00
		else:
				p2 = 0x80
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_START, 0x00, p2 ]
		params = bytearray(version.to_bytes(4, byteorder='little')) + bytearray(time.to_bytes(4, byteorder='little'))
		writeVarint(len(outputList), params)
		apdu.append(len(params))
		apdu.extend(params)
		self.dongle.exchange(bytearray(apdu))
		# Loop for each input
		currentIndex = 0
		for passedOutput in outputList:
			if ('sequence' in passedOutput) and passedOutput['sequence']:
				sequence = bytearray(unhexlify(passedOutput['sequence']))
			else:
				sequence = bytearray([0xFF, 0xFF, 0xFF, 0xFF]) # default sequence
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_START, 0x80, 0x00 ]
			params = []
			script = bytearray(redeemScript)
			if ('witness' in passedOutput) and passedOutput['witness']:
				params.append(0x02)
			elif ('trustedInput' in passedOutput) and passedOutput['trustedInput']:
				params.append(0x01)
			else:
				params.append(0x00)
			if ('trustedInput' in passedOutput) and passedOutput['trustedInput']:
				params.append(len(passedOutput['value']))
			params.extend(passedOutput['value'])
			if currentIndex != inputIndex:
				script = bytearray()
			writeVarint(len(script), params)
			if len(script) == 0:
				params.extend(sequence)
			apdu.append(len(params))
			apdu.extend(params)
			self.dongle.exchange(bytearray(apdu))
			offset = 0
			while(offset < len(script)):
				blockLength = 255
				if ((offset + blockLength) < len(script)):
					dataLength = blockLength
				else:
					dataLength = len(script) - offset
				params = script[offset : offset + dataLength]
				if ((offset + dataLength) == len(script)):
					params.extend(sequence)
				apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_START, 0x80, 0x00, len(params) ]
				apdu.extend(params)
				self.dongle.exchange(bytearray(apdu))
				offset += blockLength
			currentIndex += 1

	def finalizeInput(self, outputAddress, amount, fees, changePath, rawTx=None):
		alternateEncoding = False
		donglePath = parse_bip32_path(changePath)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(changePath)
		result = {}
		outputs = None
		if rawTx is not None:
			try:
				fullTx = bitcoinTransaction(bytearray(rawTx))
				outputs = fullTx.serializeOutputs()
				if len(donglePath) != 0:
					apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, 0xFF, 0x00 ]
					params = []
					params.extend(donglePath)
					apdu.append(len(params))
					apdu.extend(params)
					response = self.dongle.exchange(bytearray(apdu))
				offset = 0
				while (offset < len(outputs)):
					blockLength = self.scriptBlockLength
					if ((offset + blockLength) < len(outputs)):
						dataLength = blockLength
						p1 = 0x00
					else:
						dataLength = len(outputs) - offset
						p1 = 0x80
					apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, \
						p1, 0x00, dataLength ]
					apdu.extend(outputs[offset : offset + dataLength])
					response = self.dongle.exchange(bytearray(apdu))
					offset += dataLength
				alternateEncoding = True
			except:
				pass
		if not alternateEncoding:
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE, 0x02, 0x00 ]
			params = []
			params.append(len(outputAddress))
			params.extend(bytearray(outputAddress))
			writeHexAmountBE(btc_to_satoshi(str(amount)), params)
			writeHexAmountBE(btc_to_satoshi(str(fees)), params)
			params.extend(donglePath)
			apdu.append(len(params))
			apdu.extend(params)
			response = self.dongle.exchange(bytearray(apdu))
		result['confirmationNeeded'] = response[1 + response[0]] != 0x00
		result['confirmationType'] = response[1 + response[0]]
		if result['confirmationType'] == 0x02:
			result['keycardData'] = response[1 + response[0] + 1:]
		if result['confirmationType'] == 0x03:
			offset = 1 + response[0] + 1
			keycardDataLength = response[offset]
			offset = offset + 1
			result['keycardData'] = response[offset : offset + keycardDataLength]
			offset = offset + keycardDataLength
			result['secureScreenData'] = response[offset:]
		if result['confirmationType'] == 0x04:
			offset = 1 + response[0] + 1
			keycardDataLength = response[offset]
			result['keycardData'] = response[offset + 1 : offset + 1 + keycardDataLength]
		if outputs == None:
			result['outputData'] = response[1 : 1 + response[0]]
		else:
			result['outputData'] = outputs
		return result

	def finalizeInputFull(self, outputData):
		result = {}
		offset = 0
		encryptedOutputData = b""
		while (offset < len(outputData)):
			blockLength = self.scriptBlockLength
			if ((offset + blockLength) < len(outputData)):
				dataLength = blockLength
				p1 = 0x00
			else:
				dataLength = len(outputData) - offset
				p1 = 0x80
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, \
			p1, 0x00, dataLength ]
			apdu.extend(outputData[offset : offset + dataLength])
			response = self.dongle.exchange(bytearray(apdu))
			encryptedOutputData = encryptedOutputData + response[1 : 1 + response[0]]
			offset += dataLength
		if len(response) > 1:
			result['confirmationNeeded'] = response[1 + response[0]] != 0x00
			result['confirmationType'] = response[1 + response[0]]
		else:
			# Support for old style API before 1.0.2
			result['confirmationNeeded'] = response[0] != 0x00
			result['confirmationType'] = response[0]
		if result['confirmationType'] == 0x02:
			result['keycardData'] = response[1 + response[0] + 1:] # legacy
		if result['confirmationType'] == 0x03:
			offset = 1 + response[0] + 1
			keycardDataLength = response[offset]
			offset = offset + 1
			result['keycardData'] = response[offset : offset + keycardDataLength]
			offset = offset + keycardDataLength
			result['secureScreenData'] = response[offset:]
			result['encryptedOutputData'] = encryptedOutputData
		if result['confirmationType'] == 0x04:
			offset = 1 + response[0] + 1
			keycardDataLength = response[offset]
			result['keycardData'] = response[offset + 1 : offset + 1 + keycardDataLength]
		return result

	def untrustedHashSign(self, path, pin="", lockTime=0, sighashType=0x01, strdzeel=b''):
		if isinstance(pin, str):
			pin = pin.encode('utf-8')
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)

		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_SIGN, 0x01, 0x00 ]
		params = []
		writeUint32LE(lockTime, params)
		apdu.append(len(params))
		apdu.extend(params)

		result = self.dongle.exchange(bytearray(apdu))

		strdzeelSerialized = []
		writeVarint(len(strdzeel), strdzeelSerialized)
		strdzeelSerialized.extend(strdzeel)

		offset = 0

		while (offset < len(strdzeelSerialized)):
			blockLength = 255
			if ((offset + blockLength) < len(strdzeelSerialized)):
				dataLength = blockLength
			else:
				dataLength = len(strdzeelSerialized) - offset
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_SIGN, 0x01, 0x00, dataLength ]
			apdu.extend(strdzeelSerialized[offset : offset + dataLength])

			response = self.dongle.exchange(bytearray(apdu))
			offset += dataLength

		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_SIGN, 0x00, 0x00 ]
		params = []
		params.extend(donglePath)
		params.append(len(pin))
		params.extend(bytearray(pin))
		params.append(sighashType)
		apdu.append(len(params))
		apdu.extend(params)
		result = self.dongle.exchange(bytearray(apdu))
		result[0] = 0x30
		return result

	def signMessagePrepareV1(self, path, message):
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SIGN_MESSAGE, 0x00, 0x00 ]
		params = []
		params.extend(donglePath)
		params.append(len(message))
		params.extend(bytearray(message))
		apdu.append(len(params))
		apdu.extend(params)
		response = self.dongle.exchange(bytearray(apdu))
		result['confirmationNeeded'] = response[0] != 0x00
		result['confirmationType'] = response[0]
		if result['confirmationType'] == 0x02:
			result['keycardData'] = response[1:]
		if result['confirmationType'] == 0x03:
			result['secureScreenData'] = response[1:]
		return result

	def signMessagePrepareV2(self, path, message):
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)
		result = {}
		offset = 0
		encryptedOutputData = b""
		while (offset < len(message)):
			params = [];
			if offset == 0:
				params.extend(donglePath)
				params.append((len(message) >> 8) & 0xff)
				params.append(len(message) & 0xff)
				p2 = 0x01
			else:
				p2 = 0x80
			blockLength = 255 - len(params)
			if ((offset + blockLength) < len(message)):
				dataLength = blockLength
			else:
				dataLength = len(message) - offset
			params.extend(bytearray(message[offset : offset + dataLength]))
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SIGN_MESSAGE, 0x00, p2 ]
			apdu.append(len(params))
			apdu.extend(params)
			response = self.dongle.exchange(bytearray(apdu))
			encryptedOutputData = encryptedOutputData + response[1 : 1 + response[0]]
			offset += blockLength
		result['confirmationNeeded'] = response[1 + response[0]] != 0x00
		result['confirmationType'] = response[1 + response[0]]
		if result['confirmationType'] == 0x03:
			offset = 1 + response[0] + 1
			result['secureScreenData'] = response[offset:]
			result['encryptedOutputData'] = encryptedOutputData

		return result

	def signMessagePrepare(self, path, message):
		try:
			result = self.signMessagePrepareV2(path, message)
		except BTChipException as e:
			if (e.sw == 0x6b00): # Old firmware version, try older method
				result = self.signMessagePrepareV1(path, message)
			else:
				raise
		return result

	def signMessageSign(self, pin=""):
		if isinstance(pin, str):
			pin = pin.encode('utf-8')
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SIGN_MESSAGE, 0x80, 0x00 ]
		params = []
		if pin is not None:
			params.append(len(pin))
			params.extend(bytearray(pin))
		else:
			params.append(0x00)
		apdu.append(len(params))
		apdu.extend(params)
		response = self.dongle.exchange(bytearray(apdu))
		return response

	def setup(self, operationModeFlags, featuresFlag, keyVersion, keyVersionP2SH, userPin, wipePin, keymapEncoding, seed=None, developerKey=None):
		if isinstance(userPin, str):
			userPin = userPin.encode('utf-8')
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SETUP, 0x00, 0x00 ]
		params = [ operationModeFlags, featuresFlag, keyVersion, keyVersionP2SH ]
		params.append(len(userPin))
		params.extend(bytearray(userPin))
		if wipePin is not None:
			if isinstance(wipePin, str):
				wipePin = wipePin.encode('utf-8')
			params.append(len(wipePin))
			params.extend(bytearray(wipePin))
		else:
			params.append(0x00)
		if seed is not None:
			if len(seed) < 32 or len(seed) > 64:
				raise BTChipException("Invalid seed length")
			params.append(len(seed))
			params.extend(seed)
		else:
			params.append(0x00)
		if developerKey is not None:
			params.append(len(developerKey))
			params.extend(developerKey)
		else:
			params.append(0x00)
		apdu.append(len(params))
		apdu.extend(params)
		response = self.dongle.exchange(bytearray(apdu))
		result['trustedInputKey'] = response[0:16]
		result['developerKey'] = response[16:]
		self.setKeymapEncoding(keymapEncoding)
		try:
			self.setTypingBehaviour(0xff, 0xff, 0xff, 0x10)
		except BTChipException as e:
			if (e.sw == 0x6700): # Old firmware version, command not supported
				pass
			else:
				raise
		return result

	def setKeymapEncoding(self, keymapEncoding):
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SET_KEYMAP, 0x00, 0x00 ]
		apdu.append(len(keymapEncoding))
		apdu.extend(keymapEncoding)
		self.dongle.exchange(bytearray(apdu))

	def setTypingBehaviour(self, unitDelayStart, delayStart, unitDelayKey, delayKey):
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SET_KEYMAP, 0x01, 0x00 ]
		params = []
		writeUint32BE(unitDelayStart, params)
		writeUint32BE(delayStart, params)
		writeUint32BE(unitDelayKey, params)
		writeUint32BE(delayKey, params)
		apdu.append(len(params))
		apdu.extend(params)
		self.dongle.exchange(bytearray(apdu))

	def getOperationMode(self):
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_OPERATION_MODE, 0x00, 0x00, 0x00]
		response = self.dongle.exchange(bytearray(apdu))
		return response[0]

	def setOperationMode(self, operationMode):
		if operationMode != btchip.OPERATION_MODE_WALLET \
			and operationMode != btchip.OPERATION_MODE_RELAXED_WALLET \
			and operationMode != btchip.OPERATION_MODE_SERVER \
			and operationMode != btchip.OPERATION_MODE_DEVELOPER:
			raise BTChipException("Invalid operation mode")
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SET_OPERATION_MODE, 0x00, 0x00, 0x01, operationMode ]
		self.dongle.exchange(bytearray(apdu))

	def enableAlternate2fa(self, persistent):
		if persistent:
			p1 = 0x02
		else:
			p1 = 0x01
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SET_OPERATION_MODE, p1, 0x00, 0x01, btchip.OPERATION_MODE_WALLET ]
		self.dongle.exchange(bytearray(apdu))

	def getFirmwareVersion(self):
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_FIRMWARE_VERSION, 0x00, 0x00, 0x00 ]
		try:
			response = self.dongle.exchange(bytearray(apdu))
		except BTChipException as e:
			if (e.sw == 0x6985):
				response = [0x00, 0x00, 0x01, 0x04, 0x03 ]
				pass
			else:
				raise
		result['compressedKeys'] = (response[0] == 0x01)
		result['version'] = "%d.%d.%d" % (response[2], response[3], response[4])
		result['specialVersion'] = response[1]
		return result

	def getRandom(self, size):
		if size > 255:
			raise BTChipException("Invalid size")
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_RANDOM, 0x00, 0x00, size ]
		return self.dongle.exchange(bytearray(apdu))

	def getPOSSeedKey(self):
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_POS_SEED, 0x01, 0x00, 0x00 ]
		return self.dongle.exchange(bytearray(apdu))

	def getPOSEncryptedSeed(self):
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_POS_SEED, 0x02, 0x00, 0x00 ]
		return self.dongle.exchange(bytearray(apdu))

	def importPrivateKey(self, data, isSeed=False):
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_IMPORT_PRIVATE_KEY, (0x02 if isSeed else 0x01), 0x00 ]
		apdu.append(len(data))
		apdu.extend(data)
		return self.dongle.exchange(bytearray(apdu))

	def getPublicKey(self, encodedPrivateKey):
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_PUBLIC_KEY, 0x00, 0x00 ]
		apdu.append(len(encodedPrivateKey) + 1)
		apdu.append(len(encodedPrivateKey))
		apdu.extend(encodedPrivateKey)
		response = self.dongle.exchange(bytearray(apdu))
		offset = 1
		result['publicKey'] = response[offset + 1 : offset + 1 + response[offset]]
		offset = offset + 1 + response[offset]
		if response[0] == 0x02:
			result['chainCode'] = response[offset : offset + 32]
			offset = offset + 32
			result['depth'] = response[offset]
			offset = offset + 1
			result['parentFingerprint'] = response[offset : offset + 4]
			offset = offset + 4
			result['childNumber'] = response[offset : offset + 4]
		return result

	def deriveBip32Key(self, encodedPrivateKey, path):
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)
		offset = 1
		currentEncodedPrivateKey = encodedPrivateKey
		while (offset < len(donglePath)):
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_DERIVE_BIP32_KEY, 0x00, 0x00 ]
			apdu.append(len(currentEncodedPrivateKey) + 1 + 4)
			apdu.append(len(currentEncodedPrivateKey))
			apdu.extend(currentEncodedPrivateKey)
			apdu.extend(donglePath[offset : offset + 4])
			currentEncodedPrivateKey = self.dongle.exchange(bytearray(apdu))
			offset = offset + 4
		return currentEncodedPrivateKey

	def signImmediate(self, encodedPrivateKey, data, deterministic=True):
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SIGNVERIFY_IMMEDIATE, 0x00, (0x80 if deterministic else 0x00) ]
		apdu.append(len(encodedPrivateKey) + len(data) + 2);
		apdu.append(len(encodedPrivateKey))
		apdu.extend(encodedPrivateKey)
		apdu.append(len(data))
		apdu.extend(data)
		return self.dongle.exchange(bytearray(apdu))

# Functions dedicated to the Java Card interface when no proprietary API is available

	def parse_bip32_path_internal(self, path):
		if len(path) == 0:
			return []
		result = []
		elements = path.split('/')
		for pathElement in elements:
			element = pathElement.split('\'')
			if len(element) == 1:
				result.append(int(element[0]))
			else:
				result.append(0x80000000 | int(element[0]))
		return result

	def serialize_bip32_path_internal(self, path):
		result = []
		for pathElement in path:
			writeUint32BE(pathElement, result)
		return bytearray([ len(path) ] + result)

	def resolvePublicKey(self, path):
		expandedPath = self.serialize_bip32_path_internal(path)
		apdu = [ self.BTCHIP_JC_EXT_CLA, self.BTCHIP_INS_EXT_CACHE_HAS_PUBLIC_KEY, 0x00, 0x00 ]
		apdu.append(len(expandedPath))
		apdu.extend(expandedPath)
		result = self.dongle.exchange(bytearray(apdu))
		if (result[0] == 0):
			# Not present, need to be inserted into the cache
			apdu = [ self.BTCHIP_JC_EXT_CLA, self.BTCHIP_INS_EXT_GET_HALF_PUBLIC_KEY, 0x00, 0x00 ]
			apdu.append(len(expandedPath))
			apdu.extend(expandedPath)
			result = self.dongle.exchange(bytearray(apdu))
			hashData = result[0:32]
			keyX = result[32:64]
			signature = result[64:]
			keyXY = recoverKey(signature, hashData, keyX)
			apdu = [ self.BTCHIP_JC_EXT_CLA, self.BTCHIP_INS_EXT_CACHE_PUT_PUBLIC_KEY, 0x00, 0x00 ]
			apdu.append(len(expandedPath) + 65)
			apdu.extend(expandedPath)
			apdu.extend(keyXY)
			self.dongle.exchange(bytearray(apdu))

	def resolvePublicKeysInPath(self, path):
		splitPath = self.parse_bip32_path_internal(path)
		# Locate the first public key in path
		offset = 0
		startOffset = 0
		while(offset < len(splitPath)):
			if (splitPath[offset] < 0x80000000):
				startOffset = offset
				break
			offset = offset + 1
		if startOffset != 0:
			searchPath = splitPath[0:startOffset - 1]
			offset = startOffset - 1
			while(offset < len(splitPath)):
				searchPath = searchPath + [ splitPath[offset] ]
				self.resolvePublicKey(searchPath)
				offset = offset + 1
		self.resolvePublicKey(splitPath)

	def getJCExtendedFeatures(self):
		result = {}
		apdu = [ self.BTCHIP_JC_EXT_CLA, self.BTCHIP_INS_EXT_CACHE_GET_FEATURES, 0x00, 0x00, 0x00 ]
		response = self.dongle.exchange(bytearray(apdu))
		result['proprietaryApi'] = ((response[0] & 0x01) != 0)
		return result
