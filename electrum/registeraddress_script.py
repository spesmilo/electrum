from . import bitcoin
from electrum import ecc
from .util import bh2u, bfh
from .transaction import opcodes
import base64
import binascii
from .bitcoin import b58_address_to_hash160
                      
class RegisterAddressScript():
	def __init__(self, wallet):
		self.clear()
		self.wallet=wallet

	def finalize(self, ePubKey, ePrivKey=None) -> str:
		encrypted = ecc.ECPubkey(ePubKey).encrypt_message(self.payload, ephemeral=ePrivKey, encode=binascii.hexlify)
		return bh2u(bytes([opcodes.OP_REGISTERADDRESS])) + bitcoin.push_script_bytes(encrypted)

	def append(self, addrs):
		for addr in addrs:
			self.payload.extend(b58_address_to_hash160(addr)[1])
			pubkeybytes=bfh(self.wallet.get_public_key(addr, tweaked=False))
			self.payload.extend(pubkeybytes)

	def appendmulti(self, addrs, mMultisig):
		for addr in addrs:
			self.payload.append(mMultisig)

			untweakedKeys = self.wallet.get_public_keys(addr, False)
			tweakedKeys = self.wallet.get_tweaked_multi_public_keys(addr, untweakedKeys, mMultisig, False)
			tweakedKeysSorted = self.wallet.get_public_keys(addr, True)

			sortedUntweaked = []
			for i in range(len(tweakedKeysSorted)):
				for j in range(len(tweakedKeys)):
					if tweakedKeys[j] == tweakedKeysSorted[i]:
						sortedUntweaked.append(untweakedKeys[j])
						break

			self.payload.append(len(sortedUntweaked))
			self.payload.extend(b58_address_to_hash160(addr)[1]) 
			for pubkeyIt in sortedUntweaked:
				pubkeybytes=bfh(pubkeyIt)
				self.payload.extend(pubkeybytes)

	def clear(self):
		self.payload=bytearray()
		
	def size(self):
		return self.payload.size()
		
