# -*- coding: utf-8 -*-
"""Minimal Satochip card connector for the Electrum Satochip plugin.

This module is a stripped-down port of pysatochip's CardConnector
(https://github.com/Toporin/pysatochip), limited to the Satochip subset used
by this plugin. It deliberately omits everything the plugin does not need:
SeedKeeper, Satodime and Satocash support, 2FA management, factory reset,
NDEF, Schnorr/Taproot/MuSig2 signing, and encrypted seed import/export.

The only dependencies are pyscard (PC/SC transport), the cryptography library
(AES for the secure channel) and electrum_ecc (secp256k1 operations).

APDU logging is deny-by-default: command and response bodies are masked unless
the instruction is known to carry no secret material.
"""

import base64
import hashlib
import hmac
import threading
from collections import namedtuple
from os import urandom

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.util import toHexString

import electrum_ecc as ecc
from electrum_ecc import ECPubkey, ECPrivkey

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from electrum.bitcoin import usermessage_magic
from electrum.crypto import sha256d
from electrum.logging import get_logger

_logger = get_logger(__name__)

# Satochip protocol version supported by this module (see pysatochip.version)
SATOCHIP_PROTOCOL_MAJOR_VERSION = 0
SATOCHIP_PROTOCOL_MINOR_VERSION = 16

MSG_WARNING = ("Before you request coins to be sent to addresses in this "
               "wallet, ensure you can pair with your device, or that you have "
               "its seed (and passphrase, if any).  Otherwise all coins you "
               "receive will be unspendable.")

# APDU instruction codes (subset of pysatochip's JCconstants)
CardEdge_CLA = 0xB0
INS_SETUP = 0x2A
INS_VERIFY_PIN = 0x42
INS_CHANGE_PIN = 0x44
INS_GET_STATUS = 0x3C
INS_BIP32_IMPORT_SEED = 0x6C
INS_BIP32_GET_AUTHENTIKEY = 0x73
INS_BIP32_GET_EXTENDED_KEY = 0x6D
INS_INIT_SECURE_CHANNEL = 0x81
INS_PROCESS_SECURE_CHANNEL = 0x82
INS_EXPORT_PKI_CERTIFICATE = 0x93
INS_CHALLENGE_RESPONSE_PKI = 0x9A

SW_NO_MEMORY_LEFT = 0x9C01
SW_INCORRECT_INITIALIZATION = 0x9C13

PIN_INIT_VALUE = [0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30]  # default pin

SELECT = [0x00, 0xA4, 0x04, 0x00]
SATOCHIP_AID = [0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70]  # "SatoChip"

# Instructions whose APDU body carries no secret material, in either direction,
# and may therefore be rendered in full in debug logs. Anything not named here
# has its body masked.
_LOGGABLE_INS = frozenset({
    0xA4,                            # ISO SELECT: AID only
    0xFF,                            # reader pseudo-APDU
    INS_GET_STATUS,
    INS_INIT_SECURE_CHANNEL,         # ephemeral pubkey + signatures
    INS_PROCESS_SECURE_CHANNEL,      # outer wrapper; body is ciphertext
    INS_CHALLENGE_RESPONSE_PKI,
    INS_EXPORT_PKI_CERTIFICATE,
    INS_BIP32_GET_AUTHENTIKEY,
})

# a key derived through the CardConnector, as returned by the card, replayed if
# the card loses its transient derived keys (see CardConnector._restore_derived_keys)
Bip32Derivation = namedtuple('Bip32Derivation', 'path option_flags pubkey chaincode')


#################################
#         CARD  ERRORS          #
#################################

class CardError(Exception):
    """Raised when the device returns an error code"""


class CardNotPresentError(Exception):
    """Raised when no card is present on the reader"""


class CardSelectError(Exception):
    """Raised when no supported applet is found on the card"""


class CardSetupNotDoneError(Exception):
    """Raised when the card setup has not been performed"""


class UninitializedSeedError(Exception):
    """Raised when the device is not yet seeded"""


class UnexpectedSW12Error(Exception):
    """Raised when the device returns an unexpected error code"""
    def __init__(self, message, sw1=0x00, sw2=0x00):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw12hex = hex(sw1 * 256 + sw2)


class PinRequiredError(Exception):
    """Raised when the device needs a correct PIN to continue"""


class WrongPinError(Exception):
    """Raised when the provided PIN code is wrong"""
    def __init__(self, message, pin_left):
        super().__init__(message)
        self.pin_left = pin_left


class PinBlockedError(Exception):
    """Raised when the card PIN is blocked"""


class UninitializedSecureChannelError(Exception):
    """Raised when the secure channel is not initialized"""


class SecureChannelError(Exception):
    """Raised when a secure channel message is malformed or undecryptable"""


#################################
#         AES  HELPERS          #
#################################

AES_BLOCK_SIZE = 16


class InvalidPaddingError(ValueError):
    """Raised when PKCS#7 padding is malformed."""


def _pkcs7_pad(data: bytes) -> bytes:
    padsize = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return bytes(data) + bytes([padsize]) * padsize


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % AES_BLOCK_SIZE != 0:
        raise InvalidPaddingError(f"padded plaintext has invalid length {len(data)}")
    padsize = data[-1]
    if padsize < 1 or padsize > AES_BLOCK_SIZE or padsize > len(data):
        raise InvalidPaddingError(f"invalid PKCS#7 pad byte {padsize}")
    if data[-padsize:] != bytes([padsize]) * padsize:
        raise InvalidPaddingError("inconsistent PKCS#7 padding")
    return bytes(data[:-padsize])


def _aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(bytes(key)), modes.CBC(bytes(iv)))
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(bytes(data)) + op.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return _aes_cbc(key, iv, _pkcs7_pad(plaintext), encrypt=True)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise InvalidPaddingError(
            f"ciphertext length {len(ciphertext)} is not a non-zero multiple of the AES block size")
    return _pkcs7_unpad(_aes_cbc(key, iv, ciphertext, encrypt=False))


#################################
#         SECURE CHANNEL        #
#################################

class SecureChannel:
    """Encrypted channel with the card (mandatory from applet v0.11 onwards).

    ECDH on secp256k1 (raw x-coordinate as shared secret), key derivation with
    HMAC-SHA1, AES-128-CBC with PKCS#7 padding: the wire format is fixed by the
    applet.
    """

    def __init__(self):
        self.initialized_secure_channel = False
        self.sc_IVcounter = None
        self.derived_key = None
        self.mac_key = None
        # fresh ephemeral keypair per session
        self.sc_privkey = ECPrivkey.generate_random_key()
        self.sc_pubkey_serialized = self.sc_privkey.get_public_key_bytes(compressed=False)

    def initiate_secure_channel(self, peer_pubkey_bytes):
        _logger.debug("In initiate_secure_channel()")
        self.sc_IVcounter = 1
        # raw x-coordinate of privkey * peer, as derived by the applet
        peer_pubkey = ECPubkey(bytes(peer_pubkey_bytes))
        shared_point = peer_pubkey * self.sc_privkey.secret_scalar
        shared_key = shared_point.get_public_key_bytes(compressed=False)[1:33]

        mac = hmac.new(shared_key, "sc_key".encode('utf-8'), hashlib.sha1)
        self.derived_key = mac.digest()[:16]
        mac = hmac.new(shared_key, "sc_mac".encode('utf-8'), hashlib.sha1)
        self.mac_key = mac.digest()

        self.initialized_secure_channel = True

    def encrypt_secure_channel(self, data_bytes):
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        # 96 bits of randomness plus the session counter. The host uses the odd
        # counters and the applet the even ones, so the two directions can never
        # collide on an IV within a session.
        iv = urandom(12) + (self.sc_IVcounter).to_bytes(4, byteorder='big')
        ciphertext = aes_cbc_encrypt(self.derived_key, iv, data_bytes)
        self.sc_IVcounter += 2
        data_to_mac = iv + len(ciphertext).to_bytes(2, byteorder='big') + ciphertext
        mac = hmac.new(self.mac_key, data_to_mac, hashlib.sha1).digest()
        return (iv, ciphertext, mac)

    def decrypt_secure_channel(self, iv, ciphertext):
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        # The card response carries no MAC (the applet does not send one): validate
        # the shape and the padding rather than letting a mangled response through.
        if len(iv) != AES_BLOCK_SIZE:
            raise SecureChannelError(f'Wrong IV length: expected {AES_BLOCK_SIZE} got {len(iv)}')
        try:
            decrypted = aes_cbc_decrypt(self.derived_key, iv, bytes(ciphertext))
        except InvalidPaddingError as ex:
            raise SecureChannelError(f'Failed to decrypt card response: {ex}')
        return list(decrypted)


#################################
#         LOGGING               #
#################################

def _redact_apdu(apdu):
    """Hex of a command APDU for logging, with the data field masked unless the
    instruction is on _LOGGABLE_INS."""
    apdu = list(apdu)
    if len(apdu) < 5:
        return toHexString(apdu)
    if apdu[1] in _LOGGABLE_INS:
        return toHexString(apdu)
    return f"{toHexString(apdu[0:5])}{(len(apdu) - 5) * ' *'}"


def _redact_response(response, ins=None):
    """Hex of a response APDU for logging, masked unless the instruction that
    produced it is on _LOGGABLE_INS. `ins=None` means "unknown", which masks."""
    response = list(response)
    if ins in _LOGGABLE_INS:
        return toHexString(response)
    return f"({len(response)} bytes)" + len(response) * ' *'


# simple observer that logs card connection events and (redacted) APDUs
class LogCardConnectionObserver(CardConnectionObserver):
    def update(self, cardconnection, ccevent):
        if 'connect' == ccevent.type:
            _logger.info('connecting to' + repr(cardconnection.getReader()))
        elif 'disconnect' == ccevent.type:
            _logger.info('disconnecting from' + repr(cardconnection.getReader()))
        elif 'command' == ccevent.type:
            self._last_ins = ccevent.args[0][1] if len(ccevent.args[0]) > 1 else None
            _logger.debug(f"> {_redact_apdu(ccevent.args[0])}")
        elif 'response' == ccevent.type:
            if [] == ccevent.args[0]:
                _logger.debug(f'< [] {toHexString(ccevent.args[-2:])}')
            else:
                _logger.debug(f'< {_redact_response(ccevent.args[0], getattr(self, "_last_ins", None))} '
                              f'{toHexString(ccevent.args[-2:])}')


# a card observer that detects inserted/removed cards and initiates connection
class RemovalObserver(CardObserver):
    def __init__(self, cc):
        self.cc = cc
        self.observer = LogCardConnectionObserver()

    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            if card.atr == [59, 141, 1, 128, 251, 160, 0, 0, 3, 151, 66, 84, 70, 89, 4, 1, 207]:
                continue  # Ignore Windows Hello for Business virtual device
            _logger.info(f"+Inserted: {toHexString(card.atr)}")
            self.cc.card_present = True
            self.cc.cardservice = card
            self.cc.cardservice.connection = card.createConnection()
            self.cc.cardservice.connection.connect()
            self.cc.cardservice.connection.addObserver(self.observer)

            # get CPLC
            try:
                (response_CPLC, sw1, sw2) = self.cc.card_get_CPLC()
                _logger.debug(f"DEBUG CPLC: {bytes(response_CPLC).hex()}")
                (response_IIN, sw1, sw2) = self.cc.card_get_IIN()
                _logger.debug(f"DEBUG IIN: {bytes(response_IIN).hex()}")
                (response_CIN, sw1, sw2) = self.cc.card_get_CIN()
                _logger.debug(f"DEBUG CIN: {bytes(response_CIN).hex()}")
                self.cc.UID = response_CPLC + response_IIN + response_CIN
                _logger.debug(f"DEBUG UID: {bytes(self.cc.UID).hex()}")
                self.cc.UID_SHA1 = hashlib.sha1(bytes(self.cc.UID)).hexdigest()
                _logger.debug(f"DEBUG UID_SHA1: {self.cc.UID_SHA1}")
            except Exception as exc:
                _logger.warning(f"Error during CPLC/IIN/CIN: {repr(exc)}")

            # select applet
            try:
                (response, sw1, sw2) = self.cc.card_select()
                if sw1 != 0x90 or sw2 != 0x00:
                    self.cc.card_disconnect()
                    break
                (response, sw1, sw2, status) = self.cc.card_get_status()
                if (sw1 != 0x90 or sw2 != 0x00) and (sw1 != 0x9C or sw2 != 0x04):
                    self.cc.card_disconnect()
                    break
                # the secure channel is NOT initiated here: it is established
                # lazily, in the thread that first sends a command needing it
                # (see card_encrypt_secure_channel). Doing it here made this
                # monitor thread race with the client thread.
                if self.cc.client is not None:
                    self.cc.client.request('update_status', True)
            except Exception as exc:
                _logger.warning(f"Error during connection: {repr(exc)}")
                if self.cc.client is not None:
                    msg = "Exception while selecting card! Only Satochip cards are supported"
                    self.cc.client.request('show_error', msg)

        for card in removedcards:
            _logger.info(f"-Removed: {toHexString(card.atr)}")
            self.cc.card_disconnect()


#################################
#         DATA PARSER           #
#################################

class CardDataParser:
    """Parses card responses and verifies the signatures they carry.

    BIP32 responses are self-signed by the derived key and counter-signed by
    the card authentikey: the pubkeys are recovered from the signatures, which
    proves the response originates from a genuine card.
    """

    def __init__(self):
        self.authentikey = None
        self.authentikey_coordx = None
        self.authentikey_from_storage = None

    def bip32path2bytes(self, bip32path: str) -> (int, bytes):
        splitPath = bip32path.split('/')
        splitPath = [x for x in splitPath if x]  # removes empty values
        if splitPath and splitPath[0] == 'm':
            splitPath = splitPath[1:]
        bytePath = b''
        depth = len(splitPath)
        for index in splitPath:
            if index.endswith("'"):
                bytePath += (int(index.rstrip("'")) + 0x80000000).to_bytes(4, byteorder='big')
            else:
                bytePath += int(index).to_bytes(4, byteorder='big')
        return depth, bytePath

    def parse_bip32_get_authentikey(self, response):
        # response= [data_size | data | sig_size | signature]
        # where data is coordx
        _logger.debug("In parse_bip32_get_authentikey")
        data_size = ((response[0] & 0xff) << 8) + (response[1] & 0xff)
        data = response[2:(2 + data_size)]
        msg_size = 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xff) << 8) + (response[msg_size + 1] & 0xff)
        signature = response[(msg_size + 2):(msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        coordx = data
        self.authentikey = self.get_pubkey_from_signature(coordx, msg, signature)
        self.authentikey_coordx = coordx

        # if already initialized, check that authentikey matches value retrieved from storage!
        if self.authentikey_from_storage is not None:
            if self.authentikey != self.authentikey_from_storage:
                raise ValueError("The seed used to create this wallet file no longer matches "
                                 "the seed of the Satochip device!\n\n" + MSG_WARNING)
        return self.authentikey

    def parse_bip32_get_extendedkey(self, response):
        _logger.debug("In parse_bip32_get_extendedkey")
        if self.authentikey is None:
            raise ValueError("Authentikey not set!")

        # double signature: first is self-signed, second by authentikey
        chaincode = bytearray(response[0:32])
        data_size = ((response[32] & 0x7f) << 8) + (response[33] & 0xff)  # (response[32] & 0x80) is ignored (optimization flag)
        data = response[34:(32 + 2 + data_size)]
        msg_size = 32 + 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xff) << 8) + (response[msg_size + 1] & 0xff)
        signature = response[(msg_size + 2):(msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        coordx = data
        pubkey = self.get_pubkey_from_signature(coordx, msg, signature)

        # second signature by authentikey
        msg2_size = msg_size + 2 + sig_size
        msg2 = response[0:msg2_size]
        sig2_size = ((response[msg2_size] & 0xff) << 8) + (response[msg2_size + 1] & 0xff)
        signature2 = response[(msg2_size + 2):(msg2_size + 2 + sig2_size)]
        authentikey = self.get_pubkey_from_signature(self.authentikey_coordx, msg2, signature2)
        if authentikey != self.authentikey:
            raise ValueError("The seed used to create this wallet file no longer matches "
                             "the seed of the Satochip device!\n\n" + MSG_WARNING)
        return (pubkey, chaincode)

    def parse_initiate_secure_channel(self, response):
        _logger.debug("In parse_initiate_secure_channel")
        # double signature: first is self-signed, second by authentikey (optional)
        data_size = ((response[0] & 0xff) << 8) + (response[1] & 0xff)
        data = response[2:(2 + data_size)]
        msg_size = 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xff) << 8) + (response[msg_size + 1] & 0xff)
        signature = response[(msg_size + 2):(msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        coordx = data
        pubkey = self.get_pubkey_from_signature(coordx, msg, signature)

        # second signature by authentikey (optional)
        msg2_size = msg_size + 2 + sig_size
        sig2_size = ((response[msg2_size] & 0xff) << 8) + (response[msg2_size + 1] & 0xff)
        if sig2_size > 0 and self.authentikey_coordx:
            msg2 = response[0:msg2_size]
            signature2 = response[(msg2_size + 2):(msg2_size + 2 + sig2_size)]
            authentikey = self.get_pubkey_from_signature(self.authentikey_coordx, msg2, signature2)
            if authentikey.get_public_key_bytes(compressed=False) != \
                    self.authentikey.get_public_key_bytes(compressed=False):
                raise ValueError("Recovered authentikey does not correspond to registered authentikey!")
        return pubkey

    def parse_message_signature(self, response, hash, pubkey):
        _logger.debug("In parse_message_signature")
        coordx = pubkey.get_public_key_bytes()

        response = bytearray(response)
        recid = -1
        for rid in range(4):
            compsig = self.parse_to_compact_sig(response, rid, compressed=True)
            try:
                pk = ECPubkey.from_ecdsa_sig64(bytes(compsig[1:]), rid, hash)
                pkbytes = pk.get_public_key_bytes(compressed=True)
            except Exception:
                continue
            if coordx == pkbytes:
                recid = rid
                break
        if recid == -1:
            raise ValueError("Unable to recover public key from signature")
        return bytes(compsig)

    def get_pubkey_from_signature(self, coordx, data, sig):
        data = bytearray(data)
        sig = bytearray(sig)
        coordx = bytearray(coordx)

        hash = hashlib.sha256(bytes(data)).digest()

        recid = -1
        pubkey = None
        for rid in range(4):
            compsig = self.parse_to_compact_sig(sig, rid, compressed=True)
            try:
                pk = ECPubkey.from_ecdsa_sig64(bytes(compsig[1:]), rid, hash)
                pkbytes = pk.get_public_key_bytes(compressed=True)
            except Exception:
                continue
            pkbytes = pkbytes[1:]
            if coordx == pkbytes:
                recid = rid
                pubkey = pk
                break
        if recid == -1:
            raise ValueError("Unable to recover public key from signature")
        return pubkey

    def parse_to_compact_sig(self, sigin, recid, compressed):
        """Convert a DER encoded signature to compact 65-byte format."""
        sigout = bytearray(65 * [0])
        # parse input
        first = sigin[0]
        if first != 0x30:
            raise ValueError("Wrong first byte!")
        lt = sigin[1]
        check = sigin[2]
        if check != 0x02:
            raise ValueError("Check byte should be 0x02")
        # extract r
        lr = sigin[3]
        for i in range(32):
            if lr >= (i + 1):
                sigout[32 - i] = sigin[4 + lr - 1 - i]
            else:
                sigout[32 - i] = 0
        # extract s
        check = sigin[4 + lr]
        if check != 0x02:
            raise ValueError("Second check byte should be 0x02")
        ls = sigin[5 + lr]
        if lt != (lr + ls + 4):
            raise ValueError("Wrong lt value")
        for i in range(32):
            if ls >= (i + 1):
                sigout[64 - i] = sigin[5 + lr + ls - i]
            else:
                sigout[64 - i] = 0
        # 1 byte header
        if recid > 3 or recid < 0:
            raise ValueError("Wrong recid value")
        if compressed:
            sigout[0] = 27 + recid + 4
        else:
            sigout[0] = 27 + recid
        return sigout

    def convert_bytes_to_string_pem(self, cert_bytes):
        cert_bytes_b64 = base64.b64encode(bytes(cert_bytes))
        cert_b64 = cert_bytes_b64.decode('ascii')
        cert_pem = "-----BEGIN CERTIFICATE-----\r\n"
        cert_pem += '\r\n'.join([cert_b64[i:i + 64] for i in range(0, len(cert_b64), 64)])
        cert_pem += "\r\n-----END CERTIFICATE-----"
        return cert_pem

    def verify_challenge_response_pki(self, response, challenge_from_host, pubkey):
        _logger.debug("In verify_challenge_response_pki")
        # parse response
        challenge_from_device = bytes(response[0:32])
        sig_size = ((response[32] & 0xFF) << 8) + (response[33] & 0xFF)
        sig = bytes(response[34:(34 + sig_size)])
        challenge = "Challenge:".encode("utf-8") + challenge_from_device + challenge_from_host

        # parse pubkey & verify sig
        try:
            ec_pubkey = ECPubkey(bytes(pubkey))
            sig64 = ecc.ecdsa_sig64_from_der_sig(sig)
            msg32 = hashlib.sha256(challenge).digest()
            # high-S signatures are valid ECDSA and must be accepted here
            is_valid = ec_pubkey.ecdsa_verify(sig64, msg32, enforce_low_s=False)
        except ecc.InvalidECPointException:
            return False, "Invalid X9.62 encoding of the public key: " + bytes(pubkey).hex()
        except Exception as ex:
            return False, f"Exception during challenge-response verification: {ex}"
        if not is_valid:
            return False, "Bad signature during challenge response!"
        return True, ""


#################################
#         CARD CONNECTOR        #
#################################

class CardConnector:

    def __init__(self, client=None):
        _logger.debug("In __init__")
        self.parser = CardDataParser()
        self.client = client
        if self.client is not None:
            self.client.cc = self
        self.cardtype = AnyCardType()
        self.needs_2FA = None
        self.is_seeded = None
        self.setup_done = None
        self.needs_secure_channel = None
        # Secure channel. self.sc is either None or a fully initialized channel:
        # it is built lazily by whichever thread needs it first (see
        # card_ensure_secure_channel) and published only once complete, so that
        # no caller can observe a half-initialized channel. _sc_lock serializes
        # the initiation itself, so the card monitor thread and a client thread
        # cannot run two 0x81 exchanges against each other.
        self.sc = None
        self._sc_lock = threading.RLock()
        self._sc_initializing = False
        # cache PIN
        self.pin_nbr = None
        self.pin = None
        self.card_type = "card"
        self.cert_pem = None  # PEM certificate of device, if any
        # cache protocol version (version x.y => 256*x+y)
        self.protocol_version = 0
        # last BIP32 derivation, replayed if the card loses the derived key
        self._last_bip32_derivation = None  # Bip32Derivation

        # cardservice
        self.cardservice = None  # will be instantiated when a card is inserted
        try:
            self.cardrequest = CardRequest(timeout=0, cardType=self.cardtype)
            self.cardservice = self.cardrequest.waitforcard()
            self.card_present = True
        except CardRequestTimeoutException:
            self.card_present = False
        # monitor if a card is inserted or removed
        self.cardmonitor = CardMonitor()
        self.cardobserver = RemovalObserver(self)
        self.cardmonitor.addObserver(self.cardobserver)

    ###########################################
    #             Applet management           #
    ###########################################

    def card_transmit(self, plain_apdu):
        _logger.debug("In card_transmit")

        sc_retries = 0
        while self.card_present:

            # encrypt apdu
            ins = plain_apdu[1]
            if self.needs_secure_channel and (ins not in [0xA4, 0x81, 0x82, 0xFF, INS_GET_STATUS]):
                apdu = self.card_encrypt_secure_channel(plain_apdu)
            else:
                apdu = plain_apdu

            # transmit apdu
            (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)

            # PIN authentication is required
            if (sw1 == 0x9C) and (sw2 == 0x06):
                (response, sw1, sw2) = self.card_verify_PIN_simple()
            # secure channel session lost on the card side
            # 0x9C20: secure channel required (we sent plaintext)
            # 0x9C21: secure channel not initialized
            # 0x9C22: wrong IV (counter desync)
            # 0x9C23: wrong MAC (key desync)
            # The card wiped its session state (applet deselected, card reset or
            # reader power-off during an idle period). Re-establish the channel
            # and retry the APDU once with fresh keys. The retry is bounded on
            # purpose: a persistent 0x9C22/0x9C23 can also indicate tampering on
            # the PC/SC path. (ins 0x81 is the channel initiation itself: never
            # re-initiate it.)
            elif (sw1 == 0x9C) and (sw2 >= 0x20) and (sw2 <= 0x23) and (ins != 0x81):
                if sc_retries > 0:
                    return (response, sw1, sw2)
                sc_retries += 1
                _logger.warning(f"In card_transmit: secure channel error (error code {hex(256 * sw1 + sw2)}), "
                                f"re-initiating secure channel and retrying once")
                if sw2 == 0x20:
                    # the card just told us it requires a secure channel
                    self.needs_secure_channel = True
                self.card_initiate_secure_channel()
            # decrypt response
            elif (sw1 == 0x90) and (sw2 == 0x00):
                if self.needs_secure_channel and (ins not in [0xA4, 0x81, 0x82, 0xFF, INS_GET_STATUS]):
                    response = self.card_decrypt_secure_channel(response, ins)
                return (response, sw1, sw2)
            else:
                return (response, sw1, sw2)

        # no card present
        raise CardNotPresentError('No card found! Please insert card!')

    def card_get_ATR(self):
        _logger.debug('In card_get_ATR()')
        return self.cardservice.connection.getATR()

    def card_get_CPLC(self):
        cla = 0x80  # CLA_GP
        ins = 0xCA  # GPSession.INS_GET_DATA
        p1 = 0x9F
        p2 = 0x7F
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)  # bypass card_transmit checks
        return (response, sw1, sw2)

    def card_get_IIN(self):
        cla = 0x80  # CLA_GP
        ins = 0xCA  # GPSession.INS_GET_DATA
        p1 = 0x00
        p2 = 0x42
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)  # bypass card_transmit checks
        return (response, sw1, sw2)

    def card_get_CIN(self):
        cla = 0x80  # CLA_GP
        ins = 0xCA  # GPSession.INS_GET_DATA
        p1 = 0x00
        p2 = 0x45
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.cardservice.connection.transmit(apdu)  # bypass card_transmit checks
        return (response, sw1, sw2)

    def card_disconnect(self):
        _logger.debug('In card_disconnect()')
        self.pin = None  # reset PIN
        self.pin_nbr = None
        self.is_seeded = None
        self.needs_2FA = None
        self.setup_done = None
        self.needs_secure_channel = None
        self.sc = None  # a new card needs a new secure channel
        self.card_present = False
        self.card_type = "card"
        if self.cardservice:
            self.cardservice.connection.disconnect()
            self.cardservice = None
        if self.client is not None:
            self.client.request('update_status', False)
        # reset authentikey
        self.parser.authentikey = None
        self.parser.authentikey_coordx = None
        self.parser.authentikey_from_storage = None

    def get_sw12(self, sw1, sw2):
        # sw1 is the high byte: (0x9C, 0x01) is 0x9C01, which is how the
        # SW_* values are written.
        return 256 * sw1 + sw2

    def card_select(self):
        _logger.debug("In card_select")
        # selecting an applet resets the secure channel on the card side
        self.sc = None
        apdu = SELECT + [len(SATOCHIP_AID)] + SATOCHIP_AID
        (response, sw1, sw2) = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise CardSelectError("CardSelect error: no Satochip applet found on this card")
        self.card_type = "Satochip"
        _logger.debug("Found a Satochip!")
        return (response, sw1, sw2)

    def card_get_status(self):
        _logger.debug("In card_get_status")
        cla = CardEdge_CLA
        ins = INS_GET_STATUS
        p1 = 0x00
        p2 = 0x00
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.card_transmit(apdu)
        d = {}
        if (sw1 == 0x90) and (sw2 == 0x00):
            # card applet version
            d["protocol_major_version"] = response[0]
            d["protocol_minor_version"] = response[1]
            d["applet_major_version"] = response[2]
            d["applet_minor_version"] = response[3]
            d["protocol_version"] = (d["protocol_major_version"] << 8) + d["protocol_minor_version"]
            self.protocol_version = d["protocol_version"]  # cache version
            # PIN/PUK status
            if len(response) >= 8:
                d["PIN0_remaining_tries"] = response[4]
                d["PUK0_remaining_tries"] = response[5]
                d["PIN1_remaining_tries"] = response[6]
                d["PUK1_remaining_tries"] = response[7]
                self.needs_2FA = d["needs2FA"] = False  # default value
            # 2FA status
            if len(response) >= 9:
                self.needs_2FA = d["needs2FA"] = False if response[8] == 0X00 else True
            # seed status
            if len(response) >= 10:
                self.is_seeded = d["is_seeded"] = False if response[9] == 0X00 else True
            # setup status
            if len(response) >= 11:
                self.setup_done = d["setup_done"] = False if response[10] == 0X00 else True
            else:
                self.setup_done = d["setup_done"] = True
            # secure channel status
            if len(response) >= 12:
                self.needs_secure_channel = d["needs_secure_channel"] = False if response[11] == 0X00 else True
            else:
                self.needs_secure_channel = d["needs_secure_channel"] = False

        elif (sw1 == 0x9c) and (sw2 == 0x04):
            self.setup_done = d["setup_done"] = False
            self.is_seeded = d["is_seeded"] = False
            self.needs_secure_channel = d["needs_secure_channel"] = False

        else:
            _logger.warning(f"Unknown error in get_status() (error code {hex(256 * sw1 + sw2)})")

        return (response, sw1, sw2, d)

    ###########################################
    #         Generic applet methods          #
    ###########################################

    def card_get_label(self):
        _logger.debug("In card_get_label")
        cla = CardEdge_CLA
        ins = 0x3D
        p1 = 0x00
        p2 = 0x01  # get
        apdu = [cla, ins, p1, p2]
        (response, sw1, sw2) = self.card_transmit(apdu)

        if (sw1 == 0x90 and sw2 == 0x00):
            try:
                label = bytes(response[1:]).decode('utf8')
            except UnicodeDecodeError:
                _logger.warning("UnicodeDecodeError while decoding card label!")
                label = str(bytes(response[1:]))
        elif (sw1 == 0x6d and sw2 == 0x00):  # unsupported by the card
            label = '(none)'
        else:
            _logger.warning(f"Error while recovering card label: {hex(256 * sw1 + sw2)}")
            label = '(unknown)'

        return (response, sw1, sw2, label)

    def card_set_label(self, label):
        _logger.debug("In card_set_label")
        cla = CardEdge_CLA
        ins = 0x3D
        p1 = 0x00
        p2 = 0x00  # set

        label_list = list(label.encode('utf8'))
        data = [len(label_list)] + label_list
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        (response, sw1, sw2) = self.card_transmit(apdu)

        return (response, sw1, sw2)

    def card_setup(self,
                   pin_tries0, ublk_tries0, pin0, ublk0,
                   pin_tries1, ublk_tries1, pin1, ublk1,
                   memsize, memsize2,
                   create_object_ACL, create_key_ACL, create_pin_ACL):
        _logger.debug("In card_setup")

        # check pin format
        if type(pin0) == str:
            pin0 = list(pin0.encode("utf-8"))
        elif type(pin0) == bytes:
            pin0 = list(pin0)
        if type(ublk0) == str:
            ublk0 = list(ublk0.encode("utf-8"))
        elif type(ublk0) == bytes:
            ublk0 = list(ublk0)
        if type(pin1) == str:
            pin1 = list(pin1.encode("utf-8"))
        elif type(pin1) == bytes:
            pin1 = list(pin1)
        if type(ublk1) == str:
            ublk1 = list(ublk1.encode("utf-8"))
        elif type(ublk1) == bytes:
            ublk1 = list(ublk1)

        pin = PIN_INIT_VALUE
        cla = CardEdge_CLA
        ins = INS_SETUP
        p1 = 0
        p2 = 0
        apdu = [cla, ins, p1, p2]

        # data=[pin_length(1) | pin |
        #       pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 |
        #       pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 |
        #       memsize(2) | memsize2(2) | ACL(3)]
        lc = 16 + len(pin) + len(pin0) + len(pin1) + len(ublk0) + len(ublk1)

        apdu += [lc]
        apdu += [len(pin)] + pin
        apdu += [pin_tries0, ublk_tries0, len(pin0)] + pin0 + [len(ublk0)] + ublk0
        apdu += [pin_tries1, ublk_tries1, len(pin1)] + pin1 + [len(ublk1)] + ublk1
        apdu += [memsize >> 8, memsize & 0x00ff, memsize2 >> 8, memsize2 & 0x00ff]
        apdu += [create_object_ACL, create_key_ACL, create_pin_ACL]

        # send apdu (contains sensitive data!)
        (response, sw1, sw2) = self.card_transmit(apdu)
        if (sw1 == 0x90) and (sw2 == 0x00):
            self.set_pin(0, pin0)  # cache PIN value
            self.setup_done = True

        return (response, sw1, sw2)

    ###########################################
    #             BIP32 methods               #
    ###########################################

    def card_bip32_import_seed(self, seed):
        """Import a BIP32 masterseed into the device.

        Parameters:
        seed (str | bytes | list): the seed as a hex string or bytes or list of int

        Returns:
        authentikey: ECPubkey object that identifies the device
        """
        if type(seed) is str:
            seed = list(bytes.fromhex(seed))
        elif type(seed) is bytes:
            seed = list(seed)

        _logger.debug("In card_bip32_import_seed")
        cla = CardEdge_CLA
        ins = INS_BIP32_IMPORT_SEED
        p1 = len(seed)
        p2 = 0x00
        lc = len(seed)
        apdu = [cla, ins, p1, p2, lc] + seed

        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)

        # compute authentikey pubkey and send to chip for future use
        authentikey = None
        if (sw1 == 0x90) and (sw2 == 0x00):
            authentikey = self.card_bip32_set_authentikey_pubkey(response)
            authentikey_hex = authentikey.get_public_key_bytes(True).hex()
            _logger.debug('[card_bip32_import_seed] authentikey_card= ' + authentikey_hex)
            self.is_seeded = True
        elif (sw1 == 0x9C and sw2 == 0x17):
            _logger.error("Error during seed import: card is already seeded (0x9C17)")
            raise CardError('Secure import failed: card is already seeded (0x9C17)!')
        elif (sw1 == 0x9C and sw2 == 0x0F):
            _logger.error("Error during seed import: invalid parameter (0x9C0F)")
            raise CardError("Error during seed import: invalid parameter (0x9C0F)")
        else:
            # do not return a None authentikey silently: the failure would only
            # surface later, on the first command that needs the seed
            _logger.error(f"Unexpected error during seed import (error code {hex(256 * sw1 + sw2)})")
            raise UnexpectedSW12Error(
                f'Unexpected error during seed import (error code {hex(256 * sw1 + sw2)})', sw1, sw2)

        return authentikey

    def card_reset_seed(self, pin, hmac=None):
        """Reset the seed.

        Parameters:
        pin  (str | bytes | list): the pin required to unlock the device
        hmac (str | bytes | list): the 20-byte code required if 2FA is enabled

        Returns:
        (response, sw1, sw2): (list, int, int)
        """
        _logger.debug("In card_reset_seed")
        if hmac is None:
            hmac = []
        if type(pin) is str:
            pin = list(pin.encode('utf-8'))
        elif type(pin) is bytes:
            pin = list(pin)
        if type(hmac) is str:
            hmac = list(bytes.fromhex(hmac))
        elif type(hmac) is bytes:
            hmac = list(hmac)

        cla = CardEdge_CLA
        ins = 0x77
        p1 = len(pin)
        p2 = 0x00
        lc = len(pin) + len(hmac)
        apdu = [cla, ins, p1, p2, lc] + pin + hmac

        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1 == 0x90) and (sw2 == 0x00):
            self.is_seeded = False
        return (response, sw1, sw2)

    def card_bip32_get_authentikey(self):
        """Return the authentikey.

        Raises UninitializedSeedError if no seed is configured in the device.

        Returns:
        authentikey: an ECPubkey
        """
        _logger.debug("In card_bip32_get_authentikey")
        cla = CardEdge_CLA
        ins = INS_BIP32_GET_AUTHENTIKEY
        p1 = 0x00
        p2 = 0x00
        apdu = [cla, ins, p1, p2]

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x9c and sw2 == 0x14:
            _logger.info("card_bip32_get_authentikey(): Seed is not initialized => Raising error!")
            raise UninitializedSeedError("Satochip seed is not initialized!\n\n " + MSG_WARNING)
        if sw1 == 0x9c and sw2 == 0x04:
            _logger.info("card_bip32_get_authentikey(): Satochip is not initialized => Raising error!")
            raise UninitializedSeedError(
                'Satochip is not initialized! You should create a new wallet!\n\n' + MSG_WARNING)
        # compute corresponding pubkey and send to chip for future use
        authentikey = None
        if (sw1 == 0x90) and (sw2 == 0x00):
            authentikey = self.card_bip32_set_authentikey_pubkey(response)
            self.is_seeded = True
        return authentikey

    def card_bip32_set_authentikey_pubkey(self, response):
        """Compute the coordy of the authentikey externally to save computation
        time on the card; the coordy value is verified by the chip before being
        accepted."""
        _logger.debug("In card_bip32_set_authentikey_pubkey")
        cla = CardEdge_CLA
        ins = 0x75
        p1 = 0x00
        p2 = 0x00

        authentikey = self.parser.parse_bip32_get_authentikey(response)
        if authentikey:
            coordy = authentikey.get_public_key_bytes(compressed=False)
            coordy = list(coordy[33:])
            data = response + [(len(coordy) >> 8) & 0xFF, len(coordy) & 0xFF] + coordy
            lc = len(data)
            apdu = [cla, ins, p1, p2, lc] + data
            (response, sw1, sw2) = self.card_transmit(apdu)
            if sw1 != 0x90 or sw2 != 0x00:
                # This command is only an optimization for older applets (version
                # <= v0.10-0.3): it caches coordy on the chip so it does not have
                # to recompute it later. The authentikey returned below was parsed
                # (signature checked) from the caller's response, not from this
                # command, so a rejection costs performance rather than
                # correctness -- and new applets may not implement ins 0x75 at all.
                _logger.debug(
                    f"Could not cache the authentikey coordy on the card "
                    f"(error code {hex(256 * sw1 + sw2)}); continuing without it")
        return authentikey

    def card_bip32_get_extendedkey(self, path, option_flags=0x40):
        """Get the BIP32 extended pubkey for the given path.

        Parameters:
        path (str | bytes): the path; if given as a string, it is converted to
            bytes (4 bytes for each path index)

        Returns:
        (pubkey, chaincode): (ECPubkey, bytearray)
        """
        if type(path) == str:
            (depth, path) = self.parser.bip32path2bytes(path)

        _logger.debug("In card_bip32_get_extendedkey")
        cla = CardEdge_CLA
        ins = INS_BIP32_GET_EXTENDED_KEY
        p1 = len(path) // 4
        p2 = option_flags  # option flags: 0x80:erase cache memory - 0x40: optimization for non-hardened child derivation
        data = list(path)
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        # send apdu
        (response, sw1, sw2) = self.card_transmit(apdu)

        # if there is no more memory available, erase cache and retry once
        if (sw1 == 0x9C) and (sw2 == 0x01):
            _logger.info("[card_bip32_get_extendedkey] Reset memory...")
            saved_p2 = apdu[3]
            apdu[3] = saved_p2 | 0x80
            response, sw1, sw2 = self.card_transmit(apdu)
            apdu[3] = saved_p2
        # other (unexpected) error
        if (sw1 != 0x90) or (sw2 != 0x00):
            raise UnexpectedSW12Error(f'Unexpected error (error code {hex(256 * sw1 + sw2)})', sw1, sw2)

        if (response[32] & 0x80) == 0x80:
            _logger.info("[card_bip32_get_extendedkey] Child Derivation optimization...")
            (pubkey, chaincode) = self.parser.parse_bip32_get_extendedkey(response)
            coordy = pubkey.get_public_key_bytes(compressed=False)
            coordy = list(coordy[33:])
            data = response + [(len(coordy) >> 8) & 0xFF, len(coordy) & 0xFF] + coordy
            apdu_opt = [cla, 0x74, 0x00, 0x00, len(data)] + data
            # This command is only an optimization for older applets (version
            # <= v0.10-0.3): it caches coordy on the chip so it does not have to
            # recompute it later. New applets do not implement ins 0x74 at all.
            response_opt, sw1_opt, sw2_opt = self.card_transmit(apdu_opt)

        (pubkey, chaincode) = self.parser.parse_bip32_get_extendedkey(response)
        # the card now holds this key for signing with keynbr 0xFF
        self._last_bip32_derivation = Bip32Derivation(
            bytes(path), option_flags,
            pubkey.get_public_key_bytes(compressed=True), bytes(chaincode))
        return (pubkey, chaincode)

    def card_sign_message(self, keynbr, pubkey, message, hmac=b''):
        """Sign a message with the device.

        The message is prepended with the Bitcoin signed-message magic, hashed
        client-side with sha256d and signed with the SignTransactionHash command
        (ins 0x7A), supported by all applets since v0.10 (the dedicated
        SignMessage command 0x6E was removed in applet v0.16-0.0).

        Parameters:
        keynbr (int): the key to use (0xFF for bip32 key)
        pubkey (ECPubkey): the pubkey used for signing; used for key recovery
        message (bytes): the message to sign
        hmac: the 20-byte hmac code required if 2FA is enabled

        Returns:
        (response, sw1, sw2, compsig): (list, int, int, bytes)
        compsig is the signature in compact 65-byte format
        """
        _logger.debug("In card_sign_message")
        if type(message) == str:
            message = message.encode('utf8')

        # compute the message hash client-side, as done inside the card previously
        hash = sha256d(usermessage_magic(message))
        chalresponse = list(hmac) if hmac else None
        (response, sw1, sw2) = self.card_sign_transaction_hash(keynbr, list(hash), chalresponse)

        # parse signature from response
        if sw1 != 0x90 or sw2 != 0x00:
            _logger.warning(f"Unexpected error in card_sign_message() (error code {hex(256 * sw1 + sw2)})")
            compsig = b''
        else:
            compsig = self.parser.parse_message_signature(response, hash, pubkey)

        return (response, sw1, sw2, compsig)

    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse):
        """Sign a transaction hash in the device.

        Parameters:
        keynbr (int): the key to use (0xFF for bip32 key)
        txhash (list): the 32-byte transaction hash
        chalresponse (list): the hmac code if 2FA is enabled

        Returns:
        (response, sw1, sw2)
        response (list): the signature in DER format
        """
        _logger.debug("In card_sign_transaction_hash")
        cla = CardEdge_CLA
        ins = 0x7A
        p1 = keynbr
        p2 = 0x00

        if len(txhash) != 32:
            raise ValueError("Wrong txhash length: " + str(len(txhash)) + "(should be 32)")
        elif chalresponse is None:
            data = txhash
        else:
            if len(chalresponse) != 20:
                raise ValueError("Wrong Challenge response length:" + str(len(chalresponse)) + "(should be 20)")
            data = txhash + list(bytes.fromhex("8000")) + chalresponse  # 2 middle bytes for 2FA flag
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        # the card may have lost the BIP32 key: derive it again, then resend
        if keynbr == 0xFF and (256 * sw1 + sw2) == SW_INCORRECT_INITIALIZATION:
            if self._restore_derived_keys():
                response, sw1, sw2 = self.card_transmit(apdu)
        return response, sw1, sw2

    def _restore_derived_keys(self):
        """Derive again the BIP32 key after the card has lost it.

        Since applet v0.16-0.0, the BIP32 extended key (keynbr 0xFF) is
        transient: it is cleared when the applet is deselected or the card is
        reset, e.g. when another application uses the reader. card_transmit()
        then silently opens a new secure channel and verifies the cached PIN,
        but a command using the key fails with SW_INCORRECT_INITIALIZATION
        (0x9C13).

        The last derivation made through this CardConnector is replayed. It is
        only accepted if the card returns the same public key as the first
        time, so that a key is never restored on another card or from another
        seed.

        Returns True if the card holds the same key as before: the caller can
        then resend its command.
        """
        last_derivation = self._last_bip32_derivation
        if last_derivation is None:
            restored = False  # nothing was derived through this CardConnector
        else:
            try:
                try:
                    (pubkey, chaincode) = self.card_bip32_get_extendedkey(
                        last_derivation.path, last_derivation.option_flags)
                except UnexpectedSW12Error as e:
                    _logger.warning(f"The BIP32 key could not be derived again: {e}")
                    restored = False
                else:
                    restored = (pubkey.get_public_key_bytes(compressed=True) == last_derivation.pubkey
                                and bytes(chaincode) == last_derivation.chaincode)
                    if not restored:
                        _logger.warning("The BIP32 key could not be derived again: "
                                        "the card returned another pubkey")
            finally:
                # the replay records its own derivation: keep the client's one
                self._last_bip32_derivation = last_derivation

        if restored:
            _logger.info("The card had lost the derived key (0x9C13): restored")
        else:
            _logger.warning("The card has no derived key (0x9C13): derive the key "
                            "in the same card session before signing")
        return restored

    ###########################################
    #                PIN management           #
    ###########################################

    def card_verify_PIN_simple(self, pin=None):
        """Verify card PIN. Use the PIN code provided by the user first, or the
        cached PIN value if available.
        Throws exceptions for different cases:
            * CardNotPresentError if card is not inserted in reader
            * PinRequiredError if no PIN code is available
            * WrongPinError if PIN is wrong
            * PinBlockedError if PIN is blocked after too many attempts
            * UnexpectedSW12Error for other issues
        """
        _logger.debug("In card_verify_PIN_simple")

        if not self.card_present:
            raise CardNotPresentError('No card found! Please insert card!')

        if pin is not None:
            if type(pin) == str:
                pin_0 = list(pin.encode("utf-8"))
            elif type(pin) == bytes:
                pin_0 = list(pin)
            else:
                raise PinRequiredError(f'PIN should be a String or Bytes, not {type(pin)}')
        else:
            if self.pin is not None:
                # recover cached value
                pin_0 = self.pin
            else:
                raise PinRequiredError('Device cannot be unlocked without PIN code!')

        cla = CardEdge_CLA
        ins = INS_VERIFY_PIN
        apdu = [cla, ins, 0x00, 0x00, len(pin_0)] + pin_0

        if self.needs_secure_channel:
            apdu = self.card_encrypt_secure_channel(apdu)
        response, sw1, sw2 = self.cardservice.connection.transmit(apdu)

        # secure channel session lost on the card side (same recovery as card_transmit)
        if sw1 == 0x9c and 0x20 <= sw2 <= 0x23:
            _logger.warning(f"In card_verify_PIN_simple: secure channel error (error code {hex(256 * sw1 + sw2)}), "
                            f"re-initiating secure channel and retrying once")
            if sw2 == 0x20:
                # the card just told us it requires a secure channel
                self.needs_secure_channel = True
            self.card_initiate_secure_channel()
            # resend verify PIN command
            apdu = [cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
            apdu = self.card_encrypt_secure_channel(apdu)
            response, sw1, sw2 = self.cardservice.connection.transmit(apdu)

        # correct PIN: cache PIN value
        if sw1 == 0x90 and sw2 == 0x00:
            self.set_pin(0, pin_0)
            return response, sw1, sw2
        # wrong PIN, get remaining tries available (since v0.11)
        elif sw1 == 0x63 and (sw2 & 0xc0) == 0xc0:
            _logger.error("In card_verify_PIN_simple wrong PIN!")
            self.set_pin(0, None)  # reset cached PIN value
            pin_left = (sw2 & ~0xc0)
            raise WrongPinError(f"Wrong PIN! {pin_left} tries remaining!", pin_left)
        # wrong PIN (legacy before v0.11)
        elif sw1 == 0x9c and sw2 == 0x02:
            _logger.error("In card_verify_PIN_simple wrong PIN!")
            self.set_pin(0, None)  # reset cached PIN value
            (response2, sw1b, sw2b, d) = self.card_get_status()  # get number of pin tries remaining
            pin_left = d.get("PIN0_remaining_tries", -1)
            raise WrongPinError(f"Wrong PIN! {pin_left} tries remaining!", pin_left)
        # blocked PIN
        elif sw1 == 0x9c and sw2 == 0x0c:
            _logger.error("In card_verify_PIN_simple Blocked PIN!")
            self.set_pin(0, None)  # reset cached PIN value
            msg = (f"Too many failed attempts! Your device has been blocked! \n\n"
                   f"You need your PUK code to unblock it (error code {hex(256 * sw1 + sw2)})")
            raise PinBlockedError(msg)
        # card not setup
        elif sw1 == 0x9c and sw2 == 0x04:
            _logger.error("In card_verify_PIN_simple setup not done (code 0x9C04)")
            raise CardSetupNotDoneError("Failed to verify PIN: setup not done (code 0x9C04)")
        # any other edge case
        else:
            self.set_pin(0, None)  # reset cached PIN value
            msg = f"Please check your card! Unexpected error (error code {hex(256 * sw1 + sw2)})"
            raise UnexpectedSW12Error(msg, sw1, sw2)

    def card_verify_PIN(self, pin=None):
        """Verify card PIN, asking the user interactively through the client
        handler when no PIN is available or the PIN is wrong.
        """
        _logger.debug("In card_verify_PIN")

        while self.card_present:
            if pin is None:
                if self.pin is None:
                    is_PIN = False
                    if self.client is not None:
                        msg = f'Enter the PIN for your {self.card_type}:'
                        (is_PIN, pin_0) = self.client.PIN_dialog(msg)
                    if is_PIN is False:
                        raise RuntimeError('Device cannot be unlocked without correct PIN code!')
                    pin_0 = list(pin_0)
                else:
                    pin_0 = self.pin
            else:
                pin_0 = list(bytes(pin, "utf-8"))

            cla = CardEdge_CLA
            ins = INS_VERIFY_PIN
            apdu = [cla, ins, 0x00, 0x00, len(pin_0)] + pin_0

            if self.needs_secure_channel:
                apdu = self.card_encrypt_secure_channel(apdu)
            response, sw1, sw2 = self.cardservice.connection.transmit(apdu)

            # correct PIN: cache PIN value
            if sw1 == 0x90 and sw2 == 0x00:
                self.set_pin(0, pin_0)  # cache value for future use
                return (response, sw1, sw2)
            # wrong PIN, get remaining tries available (since v0.11)
            elif sw1 == 0x63 and (sw2 & 0xc0) == 0xc0:
                pin = None  # reset provided pin
                self.set_pin(0, None)  # reset cached PIN value
                pin_left = (sw2 & ~0xc0)
                msg = f"Wrong PIN! {pin_left} tries remaining!"
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise WrongPinError(msg, pin_left)
            # wrong PIN (legacy before v0.11)
            elif sw1 == 0x9c and sw2 == 0x02:
                pin = None  # reset provided pin
                self.set_pin(0, None)  # reset cached PIN value
                (response2, sw1b, sw2b, d) = self.card_get_status()  # get number of pin tries remaining
                pin_left = d.get("PIN0_remaining_tries", -1)
                msg = f"Wrong PIN! {pin_left} tries remaining!"
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise WrongPinError(msg, pin_left)
            # blocked PIN
            elif sw1 == 0x9c and sw2 == 0x0c:
                msg = (f"Too many failed attempts! Your device has been blocked! \n\n"
                       f"You need your PUK code to unblock it (error code {hex(256 * sw1 + sw2)})")
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise PinBlockedError(msg)
            elif sw1 == 0x9c and sw2 == 0x04:
                msg = "Failed to verify PIN: setup not done (code 0x9C04)"
                if self.client is not None:
                    self.client.request('show_error', msg)
                else:
                    raise CardSetupNotDoneError(msg)
            # any other edge case
            else:
                self.set_pin(0, None)  # reset cached PIN value
                msg = f"Please check your card! Unexpected error (error code {hex(256 * sw1 + sw2)})"
                if self.client is not None:
                    self.client.request('show_error', msg)
                return (response, sw1, sw2)

        if self.client is not None:
            self.client.request('show_error', 'No card found! Please insert card!')
        else:
            raise RuntimeError('No card found! Please insert card!')
        return

    def set_pin(self, pin_nbr, pin):
        self.pin_nbr = pin_nbr
        self.pin = pin
        return

    def is_pin_set(self):
        if self.pin is None:
            return False
        else:
            return True

    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        _logger.debug("In card_change_PIN")
        cla = CardEdge_CLA
        ins = INS_CHANGE_PIN
        p1 = pin_nbr
        p2 = 0x00
        lc = 1 + len(old_pin) + 1 + len(new_pin)
        apdu = [cla, ins, p1, p2, lc] + [len(old_pin)] + old_pin + [len(new_pin)] + new_pin
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)

        # correct PIN: cache new PIN value
        if sw1 == 0x90 and sw2 == 0x00:
            self.set_pin(pin_nbr, new_pin)
        # wrong PIN, get remaining tries available (since v0.11)
        elif sw1 == 0x63 and (sw2 & 0xc0) == 0xc0:
            self.set_pin(pin_nbr, None)  # reset cached PIN value
            pin_left = (sw2 & ~0xc0)
            msg = f"Wrong PIN! {pin_left} tries remaining!"
            raise WrongPinError(msg, pin_left)
        # wrong PIN (legacy before v0.11)
        elif sw1 == 0x9c and sw2 == 0x02:
            self.set_pin(pin_nbr, None)  # reset cached PIN value
            (response2, sw1b, sw2b, d) = self.card_get_status()  # get number of pin tries remaining
            pin_left = d.get("PIN0_remaining_tries", -1)
            msg = f"Wrong PIN! {pin_left} tries remaining!"
            raise WrongPinError(msg, pin_left)
        # blocked PIN
        elif sw1 == 0x9c and sw2 == 0x0c:
            msg = (f"Too many failed attempts! Your device has been blocked! \n\n"
                   f"You need your PUK code to unblock it (error code {hex(256 * sw1 + sw2)})")
            raise PinBlockedError(msg)
        else:
            # Any other status means the PIN was not changed. Raise rather than
            # return: self.pin still holds the old value, and a caller that does
            # not re-check sw1/sw2 would take this for success.
            _logger.error(f"Error during PIN change: {hex(256 * sw1 + sw2)}")
            raise UnexpectedSW12Error(
                f"Unexpected error during PIN change (error code {hex(256 * sw1 + sw2)})", sw1, sw2)

        return (response, sw1, sw2)

    ###########################################
    #             Secure channel              #
    ###########################################

    def card_initiate_secure_channel(self):
        """Establish a *new* secure channel with the card.

        The channel is built into a local object and published to self.sc only
        once it is fully usable, so another thread never sees a half-initialized
        channel. Prefer card_ensure_secure_channel() unless a fresh channel is
        specifically required (e.g. after the card returns 0x9C21).
        """
        _logger.debug("In card_initiate_secure_channel()")
        cla = CardEdge_CLA
        ins = INS_INIT_SECURE_CHANNEL
        p1 = 0x00
        p2 = 0x00

        with self._sc_lock:
            sc = SecureChannel()
            pubkey = list(sc.sc_pubkey_serialized)
            lc = len(pubkey)  # 65
            apdu = [cla, ins, p1, p2, lc] + pubkey

            # send apdu (ins 0x81 is never encrypted, see card_transmit)
            self._sc_initializing = True
            try:
                response, sw1, sw2 = self.card_transmit(apdu)
            finally:
                self._sc_initializing = False

            # On an error status the body is an error payload or empty: never
            # derive a session key from it.
            if sw1 != 0x90 or sw2 != 0x00:
                _logger.error(f"Error during secure channel initialization (error code {hex(256 * sw1 + sw2)})")
                raise UnexpectedSW12Error(
                    f"Unexpected error during secure channel initialization (error code {hex(256 * sw1 + sw2)})",
                    sw1, sw2)

            # parse response and extract pubkey
            peer_pubkey = self.parser.parse_initiate_secure_channel(response)
            peer_pubkey_bytes = peer_pubkey.get_public_key_bytes(compressed=False)
            sc.initiate_secure_channel(peer_pubkey_bytes)

            # publish the channel only once it is complete
            self.sc = sc

        return peer_pubkey

    def card_ensure_secure_channel(self):
        """Initiate the secure channel unless a usable one is already available.

        Idempotent and thread-safe: this is the single entry point through which
        the channel gets created, so callers never have to set it up themselves.
        """
        with self._sc_lock:
            if (self.sc is not None) and self.sc.initialized_secure_channel:
                return
            if self._sc_initializing:
                # reached only if a command needing encryption is sent from
                # within the 0x81 exchange itself: initiating again would recurse
                raise SecureChannelError('Secure channel is being initialized')
            _logger.debug("In card_ensure_secure_channel: no usable secure channel, initiating one")
            self.card_initiate_secure_channel()

    def card_encrypt_secure_channel(self, apdu):
        _logger.debug("In card_encrypt_secure_channel()")

        # every path that needs encryption goes through here (card_transmit,
        # card_verify_PIN_simple, card_verify_PIN), so this is where the channel
        # is guaranteed to exist
        self.card_ensure_secure_channel()

        cla = CardEdge_CLA
        ins = INS_PROCESS_SECURE_CHANNEL
        p1 = 0x00
        p2 = 0x00

        # log plaintext apdu (body masked unless the instruction is known to be
        # free of secret material -- see _LOGGABLE_INS)
        _logger.debug(f"Plaintext C-APDU: {_redact_apdu(apdu)}")

        (iv, ciphertext, mac) = self.sc.encrypt_secure_channel(bytes(apdu))
        data = (list(iv) + [len(ciphertext) >> 8, len(ciphertext) & 0xff] + list(ciphertext)
                + [len(mac) >> 8, len(mac) & 0xff] + list(mac))
        lc = len(data)

        encrypted_apdu = [cla, ins, p1, p2, lc] + data

        return encrypted_apdu

    def card_decrypt_secure_channel(self, response, ins=None):
        _logger.debug("In card_decrypt_secure_channel")

        if len(response) == 0:
            return response
        elif len(response) < 18:
            raise SecureChannelError('Encrypted response has wrong length!')

        iv = bytes(response[0:16])
        size = ((response[16] & 0xff) << 8) + (response[17] & 0xff)
        ciphertext = bytes(response[18:])
        if len(ciphertext) != size:
            _logger.warning(f"In card_decrypt_secure_channel: ciphertext has wrong length: "
                            f"expected {str(size)} got {str(len(ciphertext))}")
            raise SecureChannelError('Ciphertext has wrong length!')

        # take a reference: the channel can be dropped by the card monitor thread
        # (card removed) between the encrypted command and its response
        sc = self.sc
        if (sc is None) or (not sc.initialized_secure_channel):
            raise SecureChannelError('Secure channel was closed before the response could be decrypted!')

        plaintext = sc.decrypt_secure_channel(iv, ciphertext)

        # log response. The decrypted body routinely carries exported masterseeds,
        # so it is masked unless `ins` says otherwise.
        _logger.debug(f'Plaintext R-APDU: {_redact_response(plaintext, ins)}')

        return plaintext

    ###########################################
    #             PKI (personalization)       #
    ###########################################

    def card_export_perso_certificate(self):
        _logger.debug("In card_export_perso_certificate")
        cla = CardEdge_CLA
        ins = INS_EXPORT_PKI_CERTIFICATE
        p1 = 0x00
        p2 = 0x01  # init

        # init
        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        if (sw1 == 0x90 and sw2 == 0x00):
            pass
        elif (sw1 == 0x6D and sw2 == 0x00):
            _logger.error("Error during personalization certificate export: command unsupported (0x6D00)")
            raise CardError("Error during personalization certificate export: command unsupported (0x6D00)")
        elif (sw1 == 0x00 and sw2 == 0x00):
            _logger.error("Error during personalization certificate export: no card present (0x0000)")
            raise CardNotPresentError("Error during personalization certificate export: no card present (0x0000)")
        else:
            _logger.error(f"Error during personalization certificate export: (error code {hex(256 * sw1 + sw2)})")
            raise UnexpectedSW12Error(
                f"Error during personalization certificate export: (error code {hex(256 * sw1 + sw2)})", sw1, sw2)

        certificate_size = (response[0] & 0xFF) * 256 + (response[1] & 0xFF)
        if certificate_size == 0:
            return "(empty)"

        # UPDATE apdu: certificate data in chunks
        p2 = 0x02  # update
        certificate = certificate_size * [0]
        chunk_size = 128
        remaining_size = certificate_size
        cert_offset = 0
        while remaining_size > 128:
            # data=[ chunk_offset(2b) | chunk_size(2b) ]
            data = [((cert_offset >> 8) & 0xFF), (cert_offset & 0xFF)]
            data += [0, (chunk_size & 0xFF)]
            apdu = [cla, ins, p1, p2, len(data)] + data
            response, sw1, sw2 = self.card_transmit(apdu)
            certificate[cert_offset:(cert_offset + chunk_size)] = response[0:chunk_size]
            remaining_size -= chunk_size
            cert_offset += chunk_size

        # last chunk
        data = [((cert_offset >> 8) & 0xFF), (cert_offset & 0xFF)]
        data += [0, (remaining_size & 0xFF)]
        apdu = [cla, ins, p1, p2, len(data)] + data
        response, sw1, sw2 = self.card_transmit(apdu)
        certificate[cert_offset:(cert_offset + remaining_size)] = response[0:remaining_size]

        # parse and return raw certificate
        self.cert_pem = self.parser.convert_bytes_to_string_pem(certificate)
        return self.cert_pem

    def card_challenge_response_pki(self, pubkey):
        _logger.debug("In card_challenge_response_pki")
        cla = CardEdge_CLA
        ins = INS_CHALLENGE_RESPONSE_PKI
        p1 = 0x00
        p2 = 0x00

        challenge_from_host = urandom(32)

        apdu = [cla, ins, p1, p2, len(challenge_from_host)] + list(challenge_from_host)
        response, sw1, sw2 = self.card_transmit(apdu)

        # verify challenge-response
        verif = self.parser.verify_challenge_response_pki(response, challenge_from_host, pubkey)

        return verif
