from . import bitcoin
from electrum import ecc
from .util import bh2u
from .transaction import opcodes
import base64
                      
class RegisterAddressScript():
	def __init__(self, wallet):
		self.clear()
		self.wallet=wallet

	def finalize(self, ePubKey, ePrivKey=None) -> str:
		encrypted = ecc.ECPubkey(ePubKey).encrypt_message(self.payload, ephemeral=ePrivKey)
		return bh2u(bytes([opcodes.OP_REGISTERADDRESS])) + bitcoin.push_script_bytes(base64.b64decode(encrypted))

	def append(self, addrs):
		for addr in addrs:
			self.payload.extend(bytes(addr, 'utf-8'))
			pubkeybytes=self.wallet.get_public_key(addr, tweaked=False).encode('utf-8')
			self.payload.extend(pubkeybytes)

	def clear(self):
		self.payload=bytearray()
		
	def size(self):
		return self.payload.size()
		
