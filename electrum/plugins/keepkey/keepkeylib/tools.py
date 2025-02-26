import hashlib
import binascii
import struct
import sys

Hash = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()

HARDENED_FLAG = 1 << 31


def H_(x):
    """
    Shortcut function that "hardens" a number in a BIP44 path.
    """
    return x | HARDENED_FLAG


def btc_hash(data):
    """
    Double-SHA256 hash as used in BTC
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()


def hash_160_to_bc_address(h160, address_type):
    vh160 = chr(address_type) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)

def compress_pubkey(public_key):
    if public_key[0] == '\x04':
        return chr((ord(public_key[64]) & 1) + 2) + public_key[1:33]
    raise Exception("Pubkey is already compressed")

def public_key_to_bc_address(public_key, address_type, compress=True):
    if public_key[0] == '\x04' and compress:
        public_key = compress_pubkey(public_key)

    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, address_type)

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

if sys.version_info < (3,):
    def iterbytes(data):
        return (ord (char) for char in data)

else:
    iterbytes = lambda x: iter(x)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58."""

    long_value = 0
    for c in iterbytes(v):
        long_value = long_value * 256 + c

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in iterbytes(v):
        if c == 0:
            nPad += 1
        else:
            break

    return (__b58chars[0] * nPad) + result


def b58decode(v, length):
    """ decode v into a string of len bytes."""
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base ** i)

    result = b''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = struct.pack('B', mod) + result
        long_value = div
    result = struct.pack('B', long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = b'\x00' * nPad + result
    if length is not None and len(result) != length:
        return None

    return result


def parse_path(nstr):
    """
    Convert BIP32 path string to list of uint32 integers with hardened flags.
    Several conventions are supported to set the hardened flag: -1, 1', 1h
    e.g.: "0/1h/1" -> [0, 0x80000001, 1]
    :param nstr: path string
    :return: list of integers
    """
    if not nstr:
        return []

    n = nstr.split('/')

    # m/a/b/c => a/b/c
    if n[0] == 'm':
        n = n[1:]

    # coin_name/a/b/c => 44'/SLIP44_constant'/a/b/c
    #if n[0] in slip44:
    #    coin_id = slip44[n[0]]
    #    n[0:1] = ['44h', '{}h'.format(coin_id)]

    def str_to_harden(x):
        if x.startswith('-'):
            return H_(abs(int(x)))
        elif x.endswith(('h', "'")):
            return H_(int(x[:-1]))
        else:
            return int(x)

    try:
        return list(str_to_harden(x) for x in n)
    except Exception:
        raise ValueError('Invalid BIP32 path', nstr)


def monkeypatch_google_protobuf_text_format():
    # monkeypatching: text formatting of protobuf messages
    import google.protobuf.text_format
    import google.protobuf.descriptor

    _oldPrintFieldValue = google.protobuf.text_format.PrintFieldValue

    def _customPrintFieldValue(field, value, out, indent=0, as_utf8=False, as_one_line=False, pointy_brackets=False, float_format=None):
        if field.type == google.protobuf.descriptor.FieldDescriptor.TYPE_BYTES:
            _oldPrintFieldValue(field, 'hex(%s)' % binascii.hexlify(value), out, indent, as_utf8, as_one_line)
        else:
            _oldPrintFieldValue(field, value, out, indent, as_utf8, as_one_line)

    google.protobuf.text_format.PrintFieldValue = _customPrintFieldValue


def int_to_big_endian(value):
    import struct

    res = b''
    while 0 < value:
        res = struct.pack("B", value & 0xff) + res
        value = value >> 8

    return res

