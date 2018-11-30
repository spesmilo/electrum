import struct
import sys
import traceback
from typing import NamedTuple, Tuple, Iterable, Optional, Sequence, Union, Callable

from . import bitcoin
from . import constants
from . import ecc
from . import segwit_addr
from .bip32 import xpubkey_to_pubkey, xpubkey_to_address
from .bitcoin import hash_encode, var_int, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC, COIN, op_push, int_to_hex, \
    b58_address_to_hash160, TYPE_PUBKEY, TYPE_ADDRESS, hash160_to_p2pkh, hash160_to_p2sh, \
    hash_to_segwit_addr, TYPE_SCRIPT
from .crypto import hash_160
from .util import bh2u, bfh, print_error, to_bytes


class UnknownTxinType(Exception):
    pass


class NotRecognizedRedeemScript(Exception):
    pass


class MalformedBitcoinScript(Exception):
    pass


class TxOutput(NamedTuple):
    type: int
    address: str
    value: Union[int, str]  # str when the output is set to max: '!'


class TxOutputForUI(NamedTuple):
    address: str
    value: int


TxOutputHwInfo = NamedTuple("TxOutputHwInfo", [('address_index', Tuple),
                                               ('sorted_xpubs', Iterable[str]),
                                               ('num_sig', Optional[int]),
                                               ('script_type', str)])

NO_SIGNATURE = 'ff'
PARTIAL_TXN_HEADER_MAGIC = b'EPTF\xff'
PSBT_TXN_HEADER_MAGIC = b'psbt\xff'


# enum-like type
# From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
class EnumException(Exception):
    pass


class Enumeration:
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = {}
        reverseLookup = {}
        i = 0
        uniqueNames = []
        uniqueValues = []
        for x in enumList:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumException("enum name is not a string: " + x)
            if not isinstance(i, int):
                raise EnumException("enum value is not an integer: " + i)
            if x in uniqueNames:
                raise EnumException("enum name is not unique: " + x)
            if i in uniqueValues:
                raise EnumException("enum value is not unique for " + x)
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup

    def __getattr__(self, attr):
        if attr not in self.lookup:
            raise AttributeError
        return self.lookup[attr]

    def whatis(self, value):
        return self.reverseLookup[value]


opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1", 76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT",
    "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    ("OP_NOP1", 0xB0),
    ("OP_CHECKLOCKTIMEVERIFY", 0xB1), ("OP_CHECKSEQUENCEVERIFY", 0xB2),
    "OP_NOP4", "OP_NOP5", "OP_NOP6", "OP_NOP7", "OP_NOP8", "OP_NOP9", "OP_NOP10",
    ("OP_INVALIDOPCODE", 0xFF),
])


def script_GetOp(_bytes: bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = _bytes[i]
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                try:
                    nSize = _bytes[i]
                except IndexError:
                    raise MalformedBitcoinScript()
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                try:
                    (nSize,) = struct.unpack_from('<H', _bytes, i)
                except struct.error:
                    raise MalformedBitcoinScript()
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                try:
                    (nSize,) = struct.unpack_from('<I', _bytes, i)
                except struct.error:
                    raise MalformedBitcoinScript()
                i += 4
            vch = _bytes[i:i + nSize]
            i += nSize

        yield opcode, vch, i


def script_GetOpName(opcode):
    return (opcodes.whatis(opcode)).replace("OP_", "")


class OPPushDataGeneric:
    def __init__(self, pushlen: Callable = None):
        if pushlen is not None:
            self.check_data_len = pushlen

    @classmethod
    def check_data_len(cls, datalen: int) -> bool:
        # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        return opcodes.OP_PUSHDATA4 >= datalen >= 0

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
               or (isinstance(item, type) and issubclass(item, cls))


OPPushDataPubkey = OPPushDataGeneric(lambda x: x in (33, 65))


def match_decoded(decoded, to_match):
    # note that this does not include x_pubkeys !
    if decoded is None:
        return False
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        to_match_item = to_match[i]
        decoded_item = decoded[i]
        if OPPushDataGeneric.is_instance(to_match_item) and to_match_item.check_data_len(decoded_item[0]):
            continue
        if to_match_item != decoded_item[0]:
            return False
    return True


def parse_sig(x_sig):
    return [None if x == NO_SIGNATURE else x for x in x_sig]


def safe_parse_pubkey(x):
    try:
        return xpubkey_to_pubkey(x)
    except:
        return x


def parse_scriptSig(d, _bytes):
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except Exception as e:
        # coinbase transactions raise an exception
        print_error("parse_scriptSig: cannot find address in input script (coinbase?)",
                    bh2u(_bytes))
        return

    match = [OPPushDataGeneric]
    if match_decoded(decoded, match):
        item = decoded[0][1]
        if item[0] == 0:
            # segwit embedded into p2sh
            # witness version 0
            d['address'] = bitcoin.hash160_to_p2sh(bitcoin.hash_160(item))
            if len(item) == 22:
                d['type'] = 'p2wpkh-p2sh'
            elif len(item) == 34:
                d['type'] = 'p2wsh-p2sh'
            else:
                print_error("unrecognized txin type", bh2u(item))
        elif opcodes.OP_1 <= item[0] <= opcodes.OP_16:
            # segwit embedded into p2sh
            # witness version 1-16
            pass
        else:
            # assert item[0] == 0x30
            # pay-to-pubkey
            d['type'] = 'p2pk'
            d['address'] = "(pubkey)"
            d['signatures'] = [bh2u(item)]
            d['num_sig'] = 1
            d['x_pubkeys'] = ["(pubkey)"]
            d['pubkeys'] = ["(pubkey)"]
        return

    # p2pkh TxIn transactions push a signature
    # (71-73 bytes) and then their public key
    # (33 or 65 bytes) onto the stack:
    match = [OPPushDataGeneric, OPPushDataGeneric]
    if match_decoded(decoded, match):
        sig = bh2u(decoded[0][1])
        x_pubkey = bh2u(decoded[1][1])
        try:
            signatures = parse_sig([sig])
            pubkey, address = xpubkey_to_address(x_pubkey)
        except:
            print_error("parse_scriptSig: cannot find address in input script (p2pkh?)", bh2u(_bytes))
            return
        d['type'] = 'p2pkh'
        d['signatures'] = signatures
        d['x_pubkeys'] = [x_pubkey]
        d['num_sig'] = 1
        d['pubkeys'] = [pubkey]
        d['address'] = address
        return

    # p2sh transaction, m of n
    match = [opcodes.OP_0] + [OPPushDataGeneric] * (len(decoded) - 1)
    if match_decoded(decoded, match):
        x_sig = [bh2u(x[1]) for x in decoded[1:-1]]
        redeem_script_unsanitized = decoded[-1][1]  # for partial multisig txn, this has x_pubkeys
        try:
            m, n, x_pubkeys, pubkeys, redeem_script = parse_redeemScript_multisig(redeem_script_unsanitized)
        except NotRecognizedRedeemScript:
            print_error("parse_scriptSig: cannot find address in input script (p2sh?)", bh2u(_bytes))
            # we could still guess:
            # d['address'] = hash160_to_p2sh(hash_160(decoded[-1][1]))
            return
        # write result in d
        d['type'] = 'p2sh'
        d['num_sig'] = m
        d['signatures'] = parse_sig(x_sig)
        d['x_pubkeys'] = x_pubkeys
        d['pubkeys'] = pubkeys
        d['redeem_script'] = redeem_script
        d['address'] = hash160_to_p2sh(hash_160(bfh(redeem_script)))
        return

    # custom partial format for imported addresses
    match = [opcodes.OP_INVALIDOPCODE, opcodes.OP_0, OPPushDataGeneric]
    if match_decoded(decoded, match):
        x_pubkey = bh2u(decoded[2][1])
        pubkey, address = xpubkey_to_address(x_pubkey)
        d['type'] = 'address'
        d['address'] = address
        d['num_sig'] = 1
        d['x_pubkeys'] = [x_pubkey]
        d['pubkeys'] = None  # get_sorted_pubkeys will populate this
        d['signatures'] = [None]
        return

    print_error("parse_scriptSig: cannot find address in input script (unknown)", bh2u(_bytes))


def parse_redeemScript_multisig(redeem_script: bytes):
    try:
        dec2 = [x for x in script_GetOp(redeem_script)]
    except MalformedBitcoinScript:
        raise NotRecognizedRedeemScript()
    try:
        m = dec2[0][0] - opcodes.OP_1 + 1
        n = dec2[-2][0] - opcodes.OP_1 + 1
    except IndexError:
        raise NotRecognizedRedeemScript()
    op_m = opcodes.OP_1 + m - 1
    op_n = opcodes.OP_1 + n - 1
    match_multisig = [op_m] + [OPPushDataGeneric] * n + [op_n, opcodes.OP_CHECKMULTISIG]
    if not match_decoded(dec2, match_multisig):
        raise NotRecognizedRedeemScript()
    x_pubkeys = [bh2u(x[1]) for x in dec2[1:-2]]
    pubkeys = [safe_parse_pubkey(x) for x in x_pubkeys]
    redeem_script2 = bfh(multisig_script(x_pubkeys, m))
    if redeem_script2 != redeem_script:
        raise NotRecognizedRedeemScript()
    redeem_script_sanitized = multisig_script(pubkeys, m)
    return m, n, x_pubkeys, pubkeys, redeem_script_sanitized


def get_address_from_output_script(_bytes: bytes, *, net=None) -> Tuple[int, str]:
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except MalformedBitcoinScript:
        decoded = None

    # p2pk
    match = [OPPushDataPubkey, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match) and ecc.ECPubkey.is_pubkey_bytes(decoded[0][1]):
        return TYPE_PUBKEY, bh2u(decoded[0][1])

    # p2pkh
    match = [opcodes.OP_DUP, opcodes.OP_HASH160, OPPushDataGeneric(lambda x: x == 20), opcodes.OP_EQUALVERIFY,
             opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return TYPE_ADDRESS, hash160_to_p2pkh(decoded[2][1], net=net)

    # p2sh
    match = [opcodes.OP_HASH160, OPPushDataGeneric(lambda x: x == 20), opcodes.OP_EQUAL]
    if match_decoded(decoded, match):
        return TYPE_ADDRESS, hash160_to_p2sh(decoded[1][1], net=net)

    # segwit address (version 0)
    match = [opcodes.OP_0, OPPushDataGeneric(lambda x: x in (20, 32))]
    if match_decoded(decoded, match):
        return TYPE_ADDRESS, hash_to_segwit_addr(decoded[1][1], witver=0, net=net)

    # segwit address (version 1-16)
    future_witness_versions = list(range(opcodes.OP_1, opcodes.OP_16 + 1))
    for witver, opcode in enumerate(future_witness_versions, start=1):
        match = [opcode, OPPushDataGeneric(lambda x: 2 <= x <= 40)]
        if match_decoded(decoded, match):
            return TYPE_ADDRESS, hash_to_segwit_addr(decoded[1][1], witver=witver, net=net)

    return TYPE_SCRIPT, bh2u(_bytes)


def parse_input(vds, full_parse: bool):
    d = {}
    prevout_hash = hash_encode(vds.read_bytes(32))
    prevout_n = vds.read_uint32()
    scriptSig = vds.read_bytes(vds.read_compact_size())
    sequence = vds.read_uint32()
    d['prevout_hash'] = prevout_hash
    d['prevout_n'] = prevout_n
    d['scriptSig'] = bh2u(scriptSig)
    d['sequence'] = sequence
    d['type'] = 'unknown' if prevout_hash != '00' * 32 else 'coinbase'
    d['address'] = None
    d['num_sig'] = 0
    if not full_parse:
        return d
    d['x_pubkeys'] = []
    d['pubkeys'] = []
    d['signatures'] = {}
    if d['type'] != 'coinbase' and scriptSig:
        try:
            parse_scriptSig(d, scriptSig)
        except BaseException:
            traceback.print_exc(file=sys.stderr)
            print_error('failed to parse scriptSig', bh2u(scriptSig))
    return d


def construct_witness(items: Sequence[Union[str, int, bytes]]) -> str:
    """Constructs a witness from the given stack items."""
    witness = var_int(len(items))
    for item in items:
        if type(item) is int:
            item = bitcoin.script_num_to_hex(item)
        elif type(item) is bytes:
            item = bh2u(item)
        witness += bitcoin.witness_push(item)
    return witness


def parse_witness(vds, txin, full_parse: bool):
    n = vds.read_compact_size()
    if n == 0:
        txin['witness'] = '00'
        return
    if n == 0xffffffff:
        txin['value'] = vds.read_uint64()
        txin['witness_version'] = vds.read_uint16()
        n = vds.read_compact_size()
    # now 'n' is the number of items in the witness
    w = list(bh2u(vds.read_bytes(vds.read_compact_size())) for i in range(n))
    txin['witness'] = construct_witness(w)
    if not full_parse:
        return

    try:
        if txin.get('witness_version', 0) != 0:
            raise UnknownTxinType()
        if txin['type'] == 'coinbase':
            pass
        elif txin['type'] == 'address':
            pass
        elif txin['type'] == 'p2wsh-p2sh' or n > 2:
            witness_script_unsanitized = w[-1]  # for partial multisig txn, this has x_pubkeys
            try:
                m, n, x_pubkeys, pubkeys, witness_script = parse_redeemScript_multisig(bfh(witness_script_unsanitized))
            except NotRecognizedRedeemScript:
                raise UnknownTxinType()
            txin['signatures'] = parse_sig(w[1:-1])
            txin['num_sig'] = m
            txin['x_pubkeys'] = x_pubkeys
            txin['pubkeys'] = pubkeys
            txin['witness_script'] = witness_script
            if not txin.get('scriptSig'):  # native segwit script
                txin['type'] = 'p2wsh'
                txin['address'] = bitcoin.script_to_p2wsh(witness_script)
        elif txin['type'] == 'p2wpkh-p2sh' or n == 2:
            txin['num_sig'] = 1
            txin['x_pubkeys'] = [w[1]]
            txin['pubkeys'] = [safe_parse_pubkey(w[1])]
            txin['signatures'] = parse_sig([w[0]])
            if not txin.get('scriptSig'):  # native segwit script
                txin['type'] = 'p2wpkh'
                txin['address'] = bitcoin.public_key_to_p2wpkh(bfh(txin['pubkeys'][0]))
        else:
            raise UnknownTxinType()
    except UnknownTxinType:
        txin['type'] = 'unknown'
    except BaseException:
        txin['type'] = 'unknown'
        traceback.print_exc(file=sys.stderr)
        print_error('failed to parse witness', txin.get('witness'))


def parse_output(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    if d['value'] > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN:
        raise SerializationError('invalid output amount (too large)')
    if d['value'] < 0:
        raise SerializationError('invalid output amount (negative)')
    scriptPubKey = vds.read_bytes(vds.read_compact_size())
    d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
    d['scriptPubKey'] = bh2u(scriptPubKey)
    d['prevout_n'] = i
    return d


def deserialize(raw: str, force_full_parse=False) -> dict:
    raw_bytes = bfh(raw)
    d = {}
    if raw_bytes[:5] == PARTIAL_TXN_HEADER_MAGIC:
        d['partial'] = is_partial = True
        partial_format_version = raw_bytes[5]
        if partial_format_version != 0:
            raise SerializationError('unknown tx partial serialization format version: {}'
                                     .format(partial_format_version))
        raw_bytes = raw_bytes[6:]
    else:
        d['partial'] = is_partial = False
    full_parse = force_full_parse or is_partial
    vds = BCDataStream()
    vds.write(raw_bytes)
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    is_segwit = (n_vin == 0)
    if is_segwit:
        marker = vds.read_bytes(1)
        if marker != b'\x01':
            raise ValueError('invalid txn marker byte: {}'.format(marker))
        n_vin = vds.read_compact_size()
    d['segwit_ser'] = is_segwit
    d['inputs'] = [parse_input(vds, full_parse=full_parse) for i in range(n_vin)]
    n_vout = vds.read_compact_size()
    d['outputs'] = [parse_output(vds, i) for i in range(n_vout)]
    if is_segwit:
        for i in range(n_vin):
            txin = d['inputs'][i]
            parse_witness(vds, txin, full_parse=full_parse)
    d['lockTime'] = vds.read_uint32()
    if vds.can_read_more():
        raise SerializationError('extra junk at the end')
    return d


# pay & redeem scripts
def multisig_script(public_keys: Sequence[str], m: int) -> str:
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = format(opcodes.OP_1 + m - 1, 'x')
    op_n = format(opcodes.OP_1 + n - 1, 'x')
    keylist = [op_push(len(k) // 2) + k for k in public_keys]
    return op_m + ''.join(keylist) + op_n + 'ae'


def pay_script(output_type, addr) -> str:
    if output_type == TYPE_SCRIPT:
        return addr
    elif output_type == TYPE_ADDRESS:
        return bitcoin.address_to_script(addr)
    elif output_type == TYPE_PUBKEY:
        return bitcoin.public_key_to_p2pk_script(addr)
    else:
        raise TypeError('Unknown output type')


def estimate_pubkey_size_from_x_pubkey(x_pubkey):
    try:
        if x_pubkey[0:2] in ['02', '03']:  # compressed pubkey
            return 0x21
        elif x_pubkey[0:2] == '04':  # uncompressed pubkey
            return 0x41
        elif x_pubkey[0:2] == 'ff':  # bip32 extended pubkey
            return 0x21
        elif x_pubkey[0:2] == 'fe':  # old electrum extended pubkey
            return 0x41
    except Exception as e:
        pass
    return 0x21  # just guess it is compressed


def estimate_pubkey_size_for_txin(txin):
    pubkeys = txin.get('pubkeys', [])
    x_pubkeys = txin.get('x_pubkeys', [])
    if pubkeys and len(pubkeys) > 0:
        return estimate_pubkey_size_from_x_pubkey(pubkeys[0])
    elif x_pubkeys and len(x_pubkeys) > 0:
        return estimate_pubkey_size_from_x_pubkey(x_pubkeys[0])
    else:
        return 0x21  # just guess it is compressed


def get_sorted_pubkeys(txin: dict):
    # sort pubkeys and x_pubkeys, using the order of pubkeys
    if txin['type'] == 'coinbase':
        return [], []
    x_pubkeys = txin['x_pubkeys']
    pubkeys = txin.get('pubkeys')
    if pubkeys is None:
        pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
        pubkeys, x_pubkeys = zip(*sorted(zip(pubkeys, x_pubkeys)))
        txin['pubkeys'] = pubkeys = list(pubkeys)
        txin['x_pubkeys'] = x_pubkeys = list(x_pubkeys)
    return pubkeys, x_pubkeys


def get_siglist(txin, estimate_size=False):
    # if we have enough signatures, we use the actual pubkeys
    # otherwise, use extended pubkeys (with bip32 derivation)
    if txin['type'] == 'coinbase':
        return [], []
    num_sig = txin.get('num_sig', 1)
    if estimate_size:
        pubkey_size = estimate_pubkey_size_for_txin(txin)
        pk_list = ["00" * pubkey_size] * max(len(txin.get('x_pubkeys', [None])),
                                             txin.get('_n', 0))  # reused from PSBT code
        # we assume that signature will be 0x48 bytes long
        sig_list = ["00" * 0x48] * num_sig
    else:
        pubkeys, x_pubkeys = get_sorted_pubkeys(txin)
        x_signatures = txin['signatures']
        signatures = list(filter(None, x_signatures))
        is_complete = len(signatures) == num_sig
        if is_complete:
            pk_list = pubkeys
            sig_list = signatures
        else:
            pk_list = x_pubkeys
            sig_list = [sig if sig else NO_SIGNATURE for sig in x_signatures]
    return pk_list, sig_list


def serialize_witness(txin, estimate_size=False) -> str:
    _type = txin['type']
    if not is_segwit_input(txin) and not is_input_value_needed(txin):
        return '00'
    if _type == 'coinbase':
        return txin['witness']

    witness = txin.get('witness', None)
    if witness is None or estimate_size:
        if _type == 'address' and estimate_size:
            _type = guess_txintype_from_address(txin['address'])
        pubkeys, sig_list = get_siglist(txin, estimate_size)
        if _type in ['p2wpkh', 'p2wpkh-p2sh']:
            witness = construct_witness([sig_list[0], pubkeys[0]])
        elif _type in ['p2wsh', 'p2wsh-p2sh']:
            witness_script = multisig_script(pubkeys, txin['num_sig'])
            witness = construct_witness([0] + sig_list + [witness_script])
        else:
            witness = txin.get('witness', '00')

    if is_txin_complete(txin) or estimate_size:
        partial_format_witness_prefix = ''
    else:
        input_value = int_to_hex(txin['value'], 8)
        witness_version = int_to_hex(txin.get('witness_version', 0), 2)
        partial_format_witness_prefix = var_int(0xffffffff) + input_value + witness_version
    return partial_format_witness_prefix + witness


def is_segwit_input(txin, guess_for_address=False):
    _type = txin['type']
    if _type == 'address' and guess_for_address:
        _type = guess_txintype_from_address(txin['address'])
    has_nonzero_witness = txin.get('witness', '00') not in ('00', None)
    return is_segwit_inputtype(_type) or has_nonzero_witness


def is_segwit_input_psbt(inp, txin, guess_for_address=False):
    _type = txin['type']
    if _type == 'address' and guess_for_address:
        _type = guess_txintype_from_address(txin['address'])
    has_nonzero_witness = txin.get('witness', '00') not in ('00', None)
    return is_segwit_inputtype(_type) or has_nonzero_witness


def is_segwit_inputtype(txin_type: str) -> bool:
    return txin_type in ('p2wpkh', 'p2wpkh-p2sh', 'p2wsh', 'p2wsh-p2sh')


def is_input_value_needed(txin):
    return is_segwit_input(txin) or txin['type'] == 'address'


def guess_txintype_from_address(addr):
    # It's not possible to tell the script type in general
    # just from an address.
    # - "1" addresses are of course p2pkh
    # - "3" addresses are p2sh but we don't know the redeem script..
    # - "bc1" addresses (if they are 42-long) are p2wpkh
    # - "bc1" addresses that are 62-long are p2wsh but we don't know the script..
    # If we don't know the script, we _guess_ it is pubkeyhash.
    # As this method is used e.g. for tx size estimation,
    # the estimation will not be precise.
    witver, witprog = segwit_addr.decode(constants.net.SEGWIT_HRP, addr)
    if witprog is not None:
        return 'p2wpkh'
    addrtype, hash_160 = b58_address_to_hash160(addr)
    if addrtype == constants.net.ADDRTYPE_P2PKH:
        return 'p2pkh'
    elif addrtype == constants.net.ADDRTYPE_P2SH:
        return 'p2wpkh-p2sh'


def is_txin_complete(txin):
    if txin['type'] == 'coinbase':
        return True
    num_sig = txin.get('num_sig', 1)
    if num_sig == 0:
        return True
    x_signatures = txin.get('signatures', [])
    signatures = list(filter(None, x_signatures))
    return len(signatures) == num_sig


def serialize_outpoint(txin):
    return bh2u(bfh(txin['prevout_hash'])[::-1]) + int_to_hex(txin['prevout_n'], 4)


def get_outpoint_from_txin(txin):
    if txin['type'] == 'coinbase':
        return None
    prevout_hash = txin['prevout_hash']
    prevout_n = txin['prevout_n']
    return prevout_hash + ':%d' % prevout_n


def serialize_input(txin, script):
    # Prev hash and index
    s = serialize_outpoint(txin)
    # Script length, script, sequence
    s += var_int(len(script) // 2)
    s += script
    s += int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
    return s


def estimated_output_size(address):
    """Return an estimate of serialized output size in bytes."""
    script = bitcoin.address_to_script(address)
    # 8 byte value + 1 byte script len + script
    return 9 + len(script) // 2


def virtual_size_from_weight(weight):
    return weight // 4 + (weight % 4 > 0)


def serialize_output(output: TxOutput) -> str:
    output_type, addr, amount = output
    s = int_to_hex(amount, 8)
    script = pay_script(output_type, addr)
    s += var_int(len(script) // 2)
    s += script
    return s


def get_num_sig(redeem_script: str):
    if redeem_script is None:
        return None

    _bytes = bfh(redeem_script)

    try:
        m, n, _, pubkeys, redeem_script = parse_redeemScript_multisig(_bytes)
        num_sig = m
    except NotRecognizedRedeemScript:
        num_sig = 1
    return num_sig


class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, _bytes):  # Initialize with string of _bytes
        if self.input is None:
            self.input = bytearray(_bytes)
        else:
            self.input += bytearray(_bytes)

    def read_string(self, encoding='ascii'):
        # Strings are encoded depending on length:
        # 0 to 252 :  1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        length = self.read_compact_size()

        return self.read_bytes(length).decode(encoding)

    def write_string(self, string, encoding='ascii'):
        string = to_bytes(string, encoding)
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor + length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def can_read_more(self) -> bool:
        if not self.input:
            return False
        return self.read_cursor < len(self.input)

    def read_boolean(self):
        return self.read_bytes(1)[0] != chr(0)

    def read_int16(self):
        return self._read_num('<h')

    def read_uint16(self):
        return self._read_num('<H')

    def read_int32(self):
        return self._read_num('<i')

    def read_uint32(self):
        return self._read_num('<I')

    def read_int64(self):
        return self._read_num('<q')

    def read_uint64(self):
        return self._read_num('<Q')

    def write_boolean(self, val):
        return self.write(chr(1) if val else chr(0))

    def write_int16(self, val):
        return self._write_num('<h', val)

    def write_uint16(self, val):
        return self._write_num('<H', val)

    def write_int32(self, val):
        return self._write_num('<i', val)

    def write_uint32(self, val):
        return self._write_num('<I', val)

    def write_int64(self, val):
        return self._write_num('<q', val)

    def write_uint64(self, val):
        return self._write_num('<Q', val)

    def read_compact_size(self):
        try:
            size = self.input[self.read_cursor]
            self.read_cursor += 1
            if size == 253:
                size = self._read_num('<H')
            elif size == 254:
                size = self._read_num('<I')
            elif size == 255:
                size = self._read_num('<Q')
            return size
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(bytes([size]))
        elif size < 2 ** 16:
            self.write(b'\xfd')
            self._write_num('<H', size)
        elif size < 2 ** 32:
            self.write(b'\xfe')
            self._write_num('<I', size)
        elif size < 2 ** 64:
            self.write(b'\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        try:
            (i,) = struct.unpack_from(format, self.input, self.read_cursor)
            self.read_cursor += struct.calcsize(format)
        except Exception as e:
            raise SerializationError(e)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """
