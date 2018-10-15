import hashlib
import ecdsa
from ecdsa.util import number_to_string, string_to_number
from electroncash.bitcoin import (generator_secp256k1, point_to_ser, EC_KEY)

class Crypto(object):
    """
    This class used for tasks related to cryptography
    """

    def __init__(self):
        self.G = generator_secp256k1
        self._r = self.G.order()

    def generate_key_pair(self):
        "generate encryption/decryption pair"
        self.private_key = ecdsa.util.randrange(pow(2, 256)) % self._r
        self.eck = EC_KEY(number_to_string(self.private_key, self._r))
        self.public_key = point_to_ser(self.private_key*self.G, True)

    def export_private_key(self):
        "Export private key as hex string"
        if self.private_key:
            return bytes.hex(number_to_string(self.private_key, self._r))
        else:
            return None

    def restore_from_privkey(self, secret_string):
        "restore key pair from private key expressed in a hex form"
        self.private_key = string_to_number(bytes.fromhex(secret_string))
        self.eck = EC_KEY(bytes.fromhex(secret_string))
        self.public_key = point_to_ser(self.private_key*self.G, True)

    def export_public_key(self):
        """
        serialization of public key
        """
        return bytes.hex(self.public_key)

    def encrypt(self, message, pubkey):
        "encrypt message with pubkey"
        res = self.eck.encrypt_message(message.encode('utf-8'), bytes.fromhex(pubkey))
        return res.decode('utf-8')

    def decrypt(self, message):
        "decrypt message"
        return self.eck.decrypt_message(message)

    def hash(self, text, algorithm='sha224'):
        "method for hashing the text"
        h = hashlib.new(algorithm)
        h.update(text.encode('utf-8'))
        return h.digest()
