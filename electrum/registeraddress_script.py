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

	def append(self, addrs, nMultisig):
		for addr in addrs:
			self.payload.extend(nMultisig)
			pubkeyList = self.wallet.get_public_keys(address, nMultisig, tweaked=False)
			self.payload.extend(len(pubkeyList))
			self.payload.extend(b58_address_to_hash160(addr)[1]) 
			for pubkeyIt in pubkeyList:
				pubkeybytes=bfh(pubkeyIt)
				self.payload.extend(pubkeybytes)

	def clear(self):
		self.payload=bytearray()
		
	def size(self):
		return self.payload.size()
		
