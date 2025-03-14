import struct
import hmac
import hashlib

import ecdsa
from ecdsa.util import string_to_number, number_to_string
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point, INFINITY

from . import tools
from . import types_pb2 as proto_types

PRIME_DERIVATION_FLAG = 0x80000000

def point_to_pubkey(point):
    order = SECP256k1.order
    x_str = number_to_string(point.x(), order)
    y_str = number_to_string(point.y(), order)
    vk = x_str + y_str
    return chr((ord(vk[63]) & 1) + 2) + vk[0:32]  # To compressed key

def sec_to_public_pair(pubkey):
    """Convert a public key in sec binary format to a public pair."""
    x = string_to_number(pubkey[1:33])
    sec0 = pubkey[:1]
    if sec0 not in (b'\2', b'\3'):
        raise Exception("Compressed pubkey expected")

    def public_pair_for_x(generator, x, is_even):
        curve = generator.curve()
        p = curve.p()
        alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
        beta = ecdsa.numbertheory.square_root_mod_prime(alpha, p)
        if is_even == bool(beta & 1):
            return (x, p - beta)
        return (x, beta)

    return public_pair_for_x(ecdsa.ecdsa.generator_secp256k1, x, is_even=(sec0 == b'\2'))

def is_prime(n):
    return (bool)(n & PRIME_DERIVATION_FLAG)

def fingerprint(pubkey):
    return string_to_number(tools.hash_160(pubkey)[:4])

def get_address(public_node, address_type):
    return tools.public_key_to_bc_address(public_node.public_key, address_type)

def public_ckd(public_node, n):
    if not isinstance(n, list):
        raise Exception('Parameter must be a list')

    node = proto_types.HDNodeType()
    node.CopyFrom(public_node)

    for i in n:
        node.CopyFrom(get_subnode(node, i))

    return node

def get_subnode(node, i):
    # Public Child key derivation (CKD) algorithm of BIP32
    i_as_bytes = struct.pack(">L", i)

    if is_prime(i):
        raise Exception("Prime derivation not supported")

    # Public derivation
    data = node.public_key + i_as_bytes

    I64 = hmac.HMAC(key=node.chain_code, msg=data, digestmod=hashlib.sha512).digest()
    I_left_as_exponent = string_to_number(I64[:32])

    node_out = proto_types.HDNodeType()
    node_out.depth = node.depth + 1
    node_out.child_num = i
    node_out.chain_code = I64[32:]
    node_out.fingerprint = fingerprint(node.public_key)

    # BIP32 magic converts old public key to new public point
    x, y = sec_to_public_pair(node.public_key)
    point = I_left_as_exponent * SECP256k1.generator + \
            Point(SECP256k1.curve, x, y, SECP256k1.order)

    if point == INFINITY:
        raise Exception("Point cannot be INFINITY")

    # Convert public point to compressed public key
    node_out.public_key = point_to_pubkey(point)

    return node_out

def serialize(node, version=0x0488B21E):
    s = ''
    s += struct.pack('>I', version)
    s += struct.pack('>B', node.depth)
    s += struct.pack('>I', node.fingerprint)
    s += struct.pack('>I', node.child_num)
    s += node.chain_code
    if node.private_key:
        s += '\x00' + node.private_key
    else:
        s += node.public_key
    s += tools.Hash(s)[:4]
    return tools.b58encode(s)

def deserialize(xpub):
    data = tools.b58decode(xpub, None)

    if tools.Hash(data[:-4])[:4] != data[-4:]:
        raise Exception("Checksum failed")

    node = proto_types.HDNodeType()
    node.depth = struct.unpack('>B', data[4:5])[0]
    node.fingerprint = struct.unpack('>I', data[5:9])[0]
    node.child_num = struct.unpack('>I', data[9:13])[0]
    node.chain_code = data[13:45]

    key = data[45:-4]
    if key[0] == '\x00':
        node.private_key = key[1:]
    else:
        node.public_key = key

    return node
