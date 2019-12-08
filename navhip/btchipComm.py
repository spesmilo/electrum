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

from abc import ABCMeta, abstractmethod
from .btchipException import *
from .ledgerWrapper import wrapCommandAPDU, unwrapResponseAPDU
from binascii import hexlify
import time
import os
import struct
import socket

try:
	import hid
	HID = True
except ImportError:
	HID = False

try:
	from smartcard.Exceptions import NoCardException
	from smartcard.System import readers
	from smartcard.util import toHexString, toBytes
	SCARD = True
except ImportError:
	SCARD = False

class DongleWait(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def waitFirstResponse(self, timeout):
		pass

class Dongle(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def exchange(self, apdu, timeout=20000):
		pass

	@abstractmethod
	def close(self):
		pass

	def setWaitImpl(self, waitImpl):
		self.waitImpl = waitImpl

class HIDDongleHIDAPI(Dongle, DongleWait):

	def __init__(self, device, ledger=False, debug=False):
		self.device = device
		self.ledger = ledger		
		self.debug = debug
		self.waitImpl = self
		self.opened = True

	def exchange(self, apdu, timeout=20000):
		if self.debug:
			print("=> %s" % hexlify(apdu))
		if self.ledger:
			apdu = wrapCommandAPDU(0x0101, apdu, 64)		
		padSize = len(apdu) % 64
		tmp = apdu
		if padSize != 0:
			tmp.extend([0] * (64 - padSize))
		offset = 0
		while(offset != len(tmp)):
			data = tmp[offset:offset + 64]
			data = bytearray([0]) + data
			self.device.write(data)
			offset += 64
		dataLength = 0
		dataStart = 2		
		result = self.waitImpl.waitFirstResponse(timeout)
		if not self.ledger:
			if result[0] == 0x61: # 61xx : data available
				self.device.set_nonblocking(False)
				dataLength = result[1]
				dataLength += 2
				if dataLength > 62:
					remaining = dataLength - 62
					while(remaining != 0):
						if remaining > 64:
							blockLength = 64
						else:
							blockLength = remaining
						result.extend(bytearray(self.device.read(65))[0:blockLength])
						remaining -= blockLength
				swOffset = dataLength
				dataLength -= 2
				self.device.set_nonblocking(True)
			else:
				swOffset = 0
		else:
			self.device.set_nonblocking(False)
			while True:
				response = unwrapResponseAPDU(0x0101, result, 64)
				if response is not None:
					result = response
					dataStart = 0
					swOffset = len(response) - 2
					dataLength = len(response) - 2
					self.device.set_nonblocking(True)
					break
				result.extend(bytearray(self.device.read(65)))
		sw = (result[swOffset] << 8) + result[swOffset + 1]
		response = result[dataStart : dataLength + dataStart]
		if self.debug:
			print("<= %s%.2x" % (hexlify(response), sw))
		if sw != 0x9000:
			raise BTChipException("Invalid status %04x" % sw, sw)
		return response

	def waitFirstResponse(self, timeout):
		start = time.time()
		data = ""
		while len(data) == 0:
			data = self.device.read(65)
			if not len(data):
				if time.time() - start > timeout:
					raise BTChipException("Timeout")
				time.sleep(0.02)
		return bytearray(data)

	def close(self):
		if self.opened:
			try:
				self.device.close()
			except:
				pass
		self.opened = False

class DongleSmartcard(Dongle):

	def __init__(self, device, debug=False):
		self.device = device
		self.debug = debug
		self.waitImpl = self
		self.opened = True

	def exchange(self, apdu, timeout=20000):
		if self.debug:
			print("=> %s" % hexlify(apdu))
		response, sw1, sw2 = self.device.transmit(toBytes(hexlify(apdu)))
		sw = (sw1 << 8) | sw2
		if self.debug:
			print("<= %s%.2x" % (toHexString(response).replace(" ", ""), sw))
		if sw != 0x9000:
			raise BTChipException("Invalid status %04x" % sw, sw)
		return bytearray(response)

	def close(self):
		if self.opened:
			try:
				self.device.disconnect()
			except:
				pass
		self.opened = False

class DongleServer(Dongle):

	def __init__(self, server, port, debug=False):
		self.server = server
		self.port = port
		self.debug = debug
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.socket.connect((self.server, self.port))
		except:
			raise BTChipException("Proxy connection failed")

	def exchange(self, apdu, timeout=20000):
		if self.debug:
			print("=> %s" % hexlify(apdu))		
		self.socket.send(struct.pack(">I", len(apdu)))
		self.socket.send(apdu)
		size = struct.unpack(">I", self.socket.recv(4))[0]
		response = self.socket.recv(size)
		sw = struct.unpack(">H", self.socket.recv(2))[0]
		if self.debug:
			print("<= %s%.2x" % (hexlify(response), sw))
		if sw != 0x9000:
			raise BTChipException("Invalid status %04x" % sw, sw)
		return bytearray(response)

	def close(self):
		try:
			self.socket.close()
		except:
			pass

def getDongle(debug=False):
	dev = None
	hidDevicePath = None
	ledger = False	
	if HID:
		for hidDevice in hid.enumerate(0, 0):
			if hidDevice['vendor_id'] == 0x2581 and hidDevice['product_id'] == 0x2b7c:
				hidDevicePath = hidDevice['path']
			if hidDevice['vendor_id'] == 0x2581 and hidDevice['product_id'] == 0x3b7c:
				hidDevicePath = hidDevice['path']			
				ledger = True
			if hidDevice['vendor_id'] == 0x2581 and hidDevice['product_id'] == 0x4b7c:
				hidDevicePath = hidDevice['path']
				ledger = True
			if hidDevice['vendor_id'] == 0x2c97:
				if ('interface_number' in hidDevice and hidDevice['interface_number'] == 0) or ('usage_page' in hidDevice and hidDevice['usage_page'] == 0xffa0):
					hidDevicePath = hidDevice['path']
					ledger = True
			if hidDevice['vendor_id'] == 0x2581 and hidDevice['product_id'] == 0x1807:
				hidDevicePath = hidDevice['path']
	if hidDevicePath is not None:
		dev = hid.device()
		dev.open_path(hidDevicePath)
		dev.set_nonblocking(True)
		return HIDDongleHIDAPI(dev, ledger, debug)

	if SCARD:
		connection = None
		for reader in readers():
			try:
				connection = reader.createConnection()
				connection.connect()				
				response, sw1, sw2 = connection.transmit(toBytes("00A4040010FF4C4547522E57414C5430312E493031"))																  
				sw = (sw1 << 8) | sw2
				if sw == 0x9000:
					break
				else:
					connection.disconnect()
					connection = None
			except:
				connection = None
				pass
		if connection is not None:
			return DongleSmartcard(connection, debug)
	if (os.getenv("LEDGER_PROXY_ADDRESS") is not None) and (os.getenv("LEDGER_PROXY_PORT") is not None):
		return DongleServer(os.getenv("LEDGER_PROXY_ADDRESS"), int(os.getenv("LEDGER_PROXY_PORT")), debug)
	raise BTChipException("No dongle found")
