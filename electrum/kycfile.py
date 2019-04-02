# Copyright (c) 2018 The CommerceBlock Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# A class for read/write for an encrypted KYC file used in the user onboarding process

from io import StringIO

class CKYCFile:
	def __init__(self):
		#self.file
		#self.encryptor
		self.onboardPubKey=[]
		self.onboardUserPubKey=[]
		self.initVec=[]
		self.whitelist=[]
		self.addressKeys=[]
		self.decryptedStream=StringIO("")
		self.filename=""

	def clear(self):
		addressKeys.clear()
		decryptedStream.clear()

	def read(self):
		pass

	def write(self):
		pass

	def close(self):
		pass

	def open(self):
		pass

	def initEncryptor(self, privKey, pubKey, initVec):
		pass

	def getAddressKeys(self):
		pass

	def getOnboardPubKey(self):
		pass

	def getInitVec(self):
		pass

	def getStream(self):
		pass

	Errc = Enumeration("error codes", ["FILE_IO_ERROR", "INVALID_ADDRESS_OR_KEY","WALLET_KEY_ACCESS_ERROR",
		"WHITELIST_KEY_ACCESS_ERROR","INVALID_PARAMETER","ENCRYPTION_ERROR"])

	def getOnboardingScript(self):
		pass


