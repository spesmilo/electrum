from . import bitcoin

class RegisterAddressScript():
	def __init__(self, wallet):
		self.clear()
		self.wallet=wallet

	def finalize(self, ePubKey, ePrivKey=None) -> str:
		self.encrypted = ecc.ECPubkey(ePubKey).encrypt_message(self.payload, ephemeral=ePrivKey)
		return b2hu(opcodes.OP_REGISTERADDRESS) + bitcoin.push_script(b2hu(self.encrypted))

	def append(self, addrs):
		for addr in addrs:
			self.payload.extend(bytes(addr, 'utf-8'))
			self.payload.extend(bytes(self.wallet.get_public_keys(addr, tweaked=False)[0]))

	def clear(self):
		self.payload=bytearray()
		self.encrypted=bytearray()

	def size(self):
		return self.payload.size()
		
