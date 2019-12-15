import ecdsa
from ecdsa.util import number_to_string, string_to_number
from electrum.bitcoin import (generator_secp256k1, point_to_ser, EC_KEY,
                                  Hash, InvalidPassword)


class CryptoError(Exception):
    ''' base class of a subset of the possible exceptions raised in this class

    Subclasses have 4 items in their .args, see below '''
    pass

class DecryptError(CryptoError):
    ''' always has 4 .args:
    args[0] = programmer string message explaining what was caught
    args[1] = the wrapped exception generatede by bitcoin.py (may be InvalidPassword or Exception)
    args[2] = the private key used for decryption
    args[3] = the message that failed for decrypt '''
    pass

class EncryptError(CryptoError):
    ''' always has 4 .args:
    args[0] = programmer string message explaining what was caught
    args[1] = the wrapped exception generatede by bitcoin.py (may be InvalidPassword or Exception)
    args[2] = the public key used for encryption
    args[3] = the message that failed for decrypt '''
    pass

class Crypto:
    """ Functions related to cryptography """

    def __init__(self):
        self.G = generator_secp256k1
        self._r = self.G.order()
        self.private_key, self.eck, self.public_key = None, None, None

    def generate_key_pair(self):
        """ generate encryption/decryption pair """
        self.private_key = ecdsa.util.randrange( self._r )
        self.eck = EC_KEY(number_to_string(self.private_key, self._r))
        self.public_key = point_to_ser(self.private_key*self.G, True)

    def export_private_key(self):
        """ Export private key as hex string """
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
        """ serialization of public key """
        return bytes.hex(self.public_key)

    def encrypt(self, message, pubkey):
        """ encrypt message with pubkey """
        try:
            res = self.eck.encrypt_message(message.encode('utf-8'), bytes.fromhex(pubkey))
            return res.decode('utf-8')
        except Exception as e:  # grrr.. bitcoin.py raises 'Exception' :/
            raise EncryptError("Bitcoin.py raised '{}' during Crypto.encrypt".format(type(e).__name__), e, pubkey, message) from e

    def decrypt(self, message):
        """ decrypt message """
        try:
            return self.eck.decrypt_message(message)
        except (InvalidPassword, Exception) as e:
            raise DecryptError("Bitcoin.py raised '{}' during Crypto.decrypt".format(type(e).__name__), e, self.private_key, message) from e

    @staticmethod
    def hash(text):
        ''' Returns sha256(sha256(text)) as bytes. text may be bytes or str. '''
        return Hash(text)  # bitcoin.Hash is sha256(sha256(x))
