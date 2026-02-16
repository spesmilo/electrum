# This file is extracted and stripped down
# from https://github.com/spesmilo/electrum/blob/d17bb016ef54b6c0a99957cf3d093d0923ac6347/electrum/crypto.py
# TODO fix code duplication between repos


def versiontuple(v):
    return tuple(map(int, (v.split("."))))


def assert_bytes(*args):
    for x in args:
        assert isinstance(x, (bytes, bytearray))


HAS_CRYPTODOME = False
MIN_CRYPTODOME_VERSION = "3.7"
try:
    import Cryptodome
    if versiontuple(Cryptodome.__version__) < versiontuple(MIN_CRYPTODOME_VERSION):
        #_logger.warning(f"found module 'Cryptodome' but it is too old: {Cryptodome.__version__}<{MIN_CRYPTODOME_VERSION}")
        raise Exception()
    from Cryptodome.Cipher import ChaCha20_Poly1305 as CD_ChaCha20_Poly1305
    from Cryptodome.Cipher import ChaCha20 as CD_ChaCha20
    from Cryptodome.Cipher import AES as CD_AES
except Exception:
    #_logger.error("missing Cryptodome", exc_info=True)
    pass
else:
    HAS_CRYPTODOME = True

HAS_CRYPTOGRAPHY = False
MIN_CRYPTOGRAPHY_VERSION = "2.1"
try:
    import cryptography
    if versiontuple(cryptography.__version__) < versiontuple(MIN_CRYPTOGRAPHY_VERSION):
        #_logger.warning(f"found module 'cryptography' but it is too old: {cryptography.__version__}<{MIN_CRYPTOGRAPHY_VERSION}")
        raise Exception()
    from cryptography import exceptions
    from cryptography.hazmat.primitives.ciphers import Cipher as CG_Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as CG_algorithms
    from cryptography.hazmat.primitives.ciphers import modes as CG_modes
    from cryptography.hazmat.backends import default_backend as CG_default_backend
    import cryptography.hazmat.primitives.ciphers.aead as CG_aead
except Exception:
    #_logger.error("missing cryptography", exc_info=True)
    pass
else:
    HAS_CRYPTOGRAPHY = True


if not (HAS_CRYPTODOME or HAS_CRYPTOGRAPHY):
    raise ImportError(f"Error: at least one of ('pycryptodomex', 'cryptography') needs to be installed.")


class InvalidPadding(Exception):
    pass


def append_PKCS7_padding(data: bytes) -> bytes:
    assert_bytes(data)
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def strip_PKCS7_padding(data: bytes) -> bytes:
    assert_bytes(data)
    if len(data) % 16 != 0 or len(data) == 0:
        raise InvalidPadding("invalid length")
    padlen = data[-1]
    if not (0 < padlen <= 16):
        raise InvalidPadding("invalid padding byte (out of range)")
    for i in data[-padlen:]:
        if i != padlen:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[0:-padlen]


def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    data = append_PKCS7_padding(data)
    if HAS_CRYPTODOME:
        e = CD_AES.new(key, CD_AES.MODE_CBC, iv).encrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        encryptor = cipher.encryptor()
        e = encryptor.update(data) + encryptor.finalize()
    else:
        raise Exception("no AES backend found")
    return e


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    if HAS_CRYPTODOME:
        cipher = CD_AES.new(key, CD_AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
    else:
        raise Exception("no AES backend found")
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise
