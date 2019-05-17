from . import bitcoin
from electrum import ecc
from .util import bh2u, bfh
from .transaction import opcodes
import base64
import binascii
from bitcoin import b58check_to_bin
                      
class RegisterAddressScript():
	def __init__(self, wallet):
		self.clear()
		self.wallet=wallet

	def finalize(self, ePubKey, ePrivKey=None) -> str:
		encrypted = ecc.ECPubkey(ePubKey).encrypt_message(self.payload, ephemeral=ePrivKey, encode=binascii.hexlify)
		return bh2u(bytes([opcodes.OP_REGISTERADDRESS])) + bitcoin.push_script_bytes(encrypted)

	def append(self, addrs):
		for addr in addrs:
			self.payload.extend(b58check_to_bin(addr))
			pubkeybytes=bfh(self.wallet.get_public_key(addr, tweaked=False))
			self.payload.extend(pubkeybytes)

	def clear(self):
		self.payload=bytearray()
		
	def size(self):
		return self.payload.size()
		
