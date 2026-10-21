# Copyright (C) 2026 The Electrum developers
# Copyright (c) 2009-2010 Satoshi Nakamoto
# Copyright (c) 2009-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# Bitcoin script interpreter. Its only purpose is to check whether the inputs of a
# transaction are validly signed, i.e. whether every scriptSig/witness satisfies the
# scriptPubKey of the output it spends, under Bitcoin consensus rules.
#
# This is a port of Bitcoin Core's script interpreter (MIT licensed): src/script/interpreter.cpp,
# src/script/script.cpp, src/pubkey.cpp, src/consensus/tx_check.cpp and the sigop counting of
# src/consensus/tx_verify.cpp, as of Bitcoin Core commit 3f9c55426a12a16bd11de6dec139c4df58788360.
#
# Function names and control flow follow Core, so that the two can be compared side by side.
# Comments starting with "Core:" name the Core counterpart, or explain where the Python code
# works differently.
# VerificationBudget limits are Electrum specific. They limit the work spent on untrusted data.
# When it runs out, ResourceLimitExceeded is raised, this doesn't neccessarily mean the TX is invalid.

import enum
import hashlib
import struct
from typing import List, Optional, Sequence, Tuple

import electrum_ecc as ecc
from electrum_ecc.util import bip340_tagged_hash

from .bitcoin import (
    opcodes, var_int, witness_push, _op_push, script_num_to_bytes, construct_witness, pubkeyhash_to_p2pkh_script,
    taproot_tweak_pubkey, COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC,
)
from .crypto import sha256, sha256d, hash_160, ripemd
from .transaction import Sighash, Transaction, TxOutput


def _push_data(data: bytes) -> bytes:
    """Serialization of CScript() << data (no OP_n shortcuts, unlike bitcoin.push_script)."""
    return _op_push(len(data)) + data


# --- script.h -------------------------------------------------------------------------

MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_OPS_PER_SCRIPT = 201
MAX_PUBKEYS_PER_MULTISIG = 20
MAX_SCRIPT_SIZE = 10000
MAX_STACK_SIZE = 1000
LOCKTIME_THRESHOLD = 500000000
ANNEX_TAG = 0x50
VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50
VALIDATION_WEIGHT_OFFSET = 50

# primitives/transaction.h
SEQUENCE_FINAL = 0xffffffff
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000ffff
NULL_INDEX = 0xffffffff

# consensus/amount.h, consensus/consensus.h
MAX_MONEY = TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN
MAX_BLOCK_WEIGHT = 4_000_000
MAX_BLOCK_SIGOPS_COST = 80_000
WITNESS_SCALE_FACTOR = 4


def MoneyRange(value: int) -> bool:
    return 0 <= value <= MAX_MONEY


_DISABLED_OPCODES = frozenset((
    opcodes.OP_CAT, opcodes.OP_SUBSTR, opcodes.OP_LEFT, opcodes.OP_RIGHT,
    opcodes.OP_INVERT, opcodes.OP_AND, opcodes.OP_OR, opcodes.OP_XOR,
    opcodes.OP_2MUL, opcodes.OP_2DIV, opcodes.OP_MUL, opcodes.OP_DIV, opcodes.OP_MOD, opcodes.OP_LSHIFT, opcodes.OP_RSHIFT,
))
_UPGRADABLE_NOPS = frozenset((
    opcodes.OP_NOP1, opcodes.OP_NOP4, opcodes.OP_NOP5, opcodes.OP_NOP6,
    opcodes.OP_NOP7, opcodes.OP_NOP8, opcodes.OP_NOP9, opcodes.OP_NOP10,
))


def IsOpSuccess(opcode: int) -> bool:
    """Test for OP_SUCCESSx opcodes as defined by BIP342."""
    return (opcode == 80 or opcode == 98 or (126 <= opcode <= 129) or (131 <= opcode <= 134)
            or (137 <= opcode <= 138) or (141 <= opcode <= 142) or (149 <= opcode <= 153)
            or (187 <= opcode <= 254))


_IS_OP_SUCCESS = tuple(IsOpSuccess(i) for i in range(256))


def GetScriptOp(script: bytes, pc: int) -> Tuple[bool, int, bytes, int]:
    """Returns (success, opcode, push_data, new_pc).
    Core: pc is passed by reference. On failure, new_pc is where Core's iterator is left
    (which matters for SerializeScriptCode)."""
    end = len(script)
    if pc >= end:
        return False, opcodes.OP_INVALIDOPCODE, b'', pc
    opcode = script[pc]
    pc += 1
    if opcode <= opcodes.OP_PUSHDATA4:
        if opcode < opcodes.OP_PUSHDATA1:
            n_size = opcode
        elif opcode == opcodes.OP_PUSHDATA1:
            if end - pc < 1:
                return False, opcodes.OP_INVALIDOPCODE, b'', pc
            n_size = script[pc]
            pc += 1
        elif opcode == opcodes.OP_PUSHDATA2:
            if end - pc < 2:
                return False, opcodes.OP_INVALIDOPCODE, b'', pc
            n_size = int.from_bytes(script[pc:pc + 2], 'little')
            pc += 2
        else:
            if end - pc < 4:
                return False, opcodes.OP_INVALIDOPCODE, b'', pc
            n_size = int.from_bytes(script[pc:pc + 4], 'little')
            pc += 4
        if end - pc < n_size:
            return False, opcodes.OP_INVALIDOPCODE, b'', pc
        return True, opcode, script[pc:pc + n_size], pc + n_size
    return True, opcode, b'', pc


def _next_op(script: bytes, pc: int, end: int) -> int:
    """Position after the op at pc, or -1 if GetScriptOp fails. Requires pc < end."""
    opcode = script[pc]
    pc += 1
    if opcode > opcodes.OP_PUSHDATA4:
        return pc
    if opcode < opcodes.OP_PUSHDATA1:
        n_size = opcode
    elif opcode == opcodes.OP_PUSHDATA1:
        if end - pc < 1:
            return -1
        n_size = script[pc]
        pc += 1
    elif opcode == opcodes.OP_PUSHDATA2:
        if end - pc < 2:
            return -1
        n_size = script[pc] | (script[pc + 1] << 8)
        pc += 2
    else:
        if end - pc < 4:
            return -1
        n_size = int.from_bytes(script[pc:pc + 4], 'little')
        pc += 4
    if end - pc < n_size:
        return -1
    return pc + n_size


def IsPushOnly(script: bytes) -> bool:
    pc = 0
    end = len(script)
    while pc < end:
        if script[pc] > opcodes.OP_16:
            return False
        pc = _next_op(script, pc, end)
        if pc < 0:
            return False
    return True


def IsPayToScriptHash(script: bytes) -> bool:
    return len(script) == 23 and script[0] == opcodes.OP_HASH160 and script[1] == 0x14 and script[22] == opcodes.OP_EQUAL


def IsWitnessProgram(script: bytes) -> Optional[Tuple[int, bytes]]:
    """Returns (version, program), or None.
    A witness program is any valid script that consists of a 1-byte push opcode
    followed by a data push between 2 and 40 bytes."""
    if len(script) < 4 or len(script) > 42:
        return None
    if script[0] != opcodes.OP_0 and (script[0] < opcodes.OP_1 or script[0] > opcodes.OP_16):
        return None
    if script[1] + 2 == len(script):
        version = 0 if script[0] == opcodes.OP_0 else script[0] - (opcodes.OP_1 - 1)
        return version, script[2:]
    return None


def IsPayToAnchor(version: int, program: bytes) -> bool:
    return version == 1 and program == b'\x4e\x73'


def GetSigOpCount(script: bytes, accurate: bool) -> int:
    """Core: CScript::GetSigOpCount(bool fAccurate)"""
    n = 0
    pc = 0
    end = len(script)
    last_opcode = opcodes.OP_INVALIDOPCODE
    while pc < end:
        opcode = script[pc]
        pc = _next_op(script, pc, end)
        if pc < 0:
            break
        if opcode == opcodes.OP_CHECKSIG or opcode == opcodes.OP_CHECKSIGVERIFY:
            n += 1
        elif opcode == opcodes.OP_CHECKMULTISIG or opcode == opcodes.OP_CHECKMULTISIGVERIFY:
            if accurate and opcodes.OP_1 <= last_opcode <= opcodes.OP_16:
                n += last_opcode - (opcodes.OP_1 - 1)
            else:
                n += MAX_PUBKEYS_PER_MULTISIG
        last_opcode = opcode
    return n


def GetSigOpCountWithScriptSig(script: bytes, script_sig: bytes) -> int:
    """Core: CScript::GetSigOpCount(const CScript& scriptSig)"""
    if not IsPayToScriptHash(script):
        return GetSigOpCount(script, True)

    # This is a pay-to-script-hash scriptPubKey;
    # get the last item that the scriptSig
    # pushes onto the stack:
    pc = 0
    data = b''
    while pc < len(script_sig):
        ok, opcode, data, pc = GetScriptOp(script_sig, pc)
        if not ok:
            return 0
        if opcode > opcodes.OP_16:
            return 0

    # ... and return its opcount:
    return GetSigOpCount(data, True)


def CheckMinimalPush(data: bytes, opcode: int) -> bool:
    # Excludes OP_1NEGATE, OP_1-16 since they are by definition minimal
    assert 0 <= opcode <= opcodes.OP_PUSHDATA4
    n = len(data)
    if n == 0:
        # Should have used OP_0.
        return opcode == opcodes.OP_0
    elif n == 1 and 1 <= data[0] <= 16:
        # Should have used OP_1 .. OP_16.
        return False
    elif n == 1 and data[0] == 0x81:
        # Should have used OP_1NEGATE.
        return False
    elif n <= 75:
        # Must have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == n
    elif n <= 255:
        # Must have used OP_PUSHDATA.
        return opcode == opcodes.OP_PUSHDATA1
    elif n <= 65535:
        # Must have used OP_PUSHDATA2.
        return opcode == opcodes.OP_PUSHDATA2
    return True


class ScriptNumError(Exception):
    """Core: scriptnum_error"""


def CScriptNum(vch: bytes, require_minimal: bool, max_num_size: int = 4) -> int:
    """Decodes a script number. Core: CScriptNum(vch, fRequireMinimal, nMaxNumSize)"""
    if len(vch) > max_num_size:
        raise ScriptNumError("script number overflow")
    if require_minimal and len(vch) > 0:
        # Check that the number is encoded with the minimum possible number of bytes.
        # If the most-significant-byte - excluding the sign bit - is zero then we're not minimal.
        # Note how this test also rejects the negative-zero encoding, 0x80.
        if (vch[-1] & 0x7f) == 0:
            # One exception: if there's more than one byte and the most significant bit of the
            # second-most-significant-byte is set it would conflict with the sign bit.
            if len(vch) <= 1 or (vch[-2] & 0x80) == 0:
                raise ScriptNumError("non-minimally encoded script number")
    if not vch:
        return 0
    result = int.from_bytes(vch, 'little')
    # If the input vector's most significant byte is 0x80, remove it from the result's msb
    # and return a negative.
    if vch[-1] & 0x80:
        return -(result & ~(0x80 << (8 * (len(vch) - 1))))
    return result


def _getint(value: int) -> int:
    """Core: CScriptNum::getint, which saturates to the int32 range."""
    if value > 0x7fffffff:
        return 0x7fffffff
    if value < -0x80000000:
        return -0x80000000
    return value


# --- script_error.h -------------------------------------------------------------------

class ScriptError(enum.Enum):
    # Member names equal the strings used by Core's script tests (FormatScriptError).
    OK = 0
    UNKNOWN_ERROR = 1
    EVAL_FALSE = 2
    OP_RETURN = 3
    SCRIPTNUM = 4
    # Max sizes
    SCRIPT_SIZE = 5
    PUSH_SIZE = 6
    OP_COUNT = 7
    STACK_SIZE = 8
    SIG_COUNT = 9
    PUBKEY_COUNT = 10
    # Failed verify operations
    VERIFY = 11
    EQUALVERIFY = 12
    CHECKMULTISIGVERIFY = 13
    CHECKSIGVERIFY = 14
    NUMEQUALVERIFY = 15
    # Logical/Format/Canonical errors
    BAD_OPCODE = 16
    DISABLED_OPCODE = 17
    INVALID_STACK_OPERATION = 18
    INVALID_ALTSTACK_OPERATION = 19
    UNBALANCED_CONDITIONAL = 20
    # CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
    NEGATIVE_LOCKTIME = 21
    UNSATISFIED_LOCKTIME = 22
    # Malleability
    SIG_HASHTYPE = 23
    SIG_DER = 24
    MINIMALDATA = 25
    SIG_PUSHONLY = 26
    SIG_HIGH_S = 27
    SIG_NULLDUMMY = 28
    PUBKEYTYPE = 29
    CLEANSTACK = 30
    MINIMALIF = 31
    NULLFAIL = 32  # Core: SCRIPT_ERR_SIG_NULLFAIL
    # softfork safeness
    DISCOURAGE_UPGRADABLE_NOPS = 33
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 34
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 35
    DISCOURAGE_OP_SUCCESS = 36
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 37
    # segregated witness
    WITNESS_PROGRAM_WRONG_LENGTH = 38
    WITNESS_PROGRAM_WITNESS_EMPTY = 39
    WITNESS_PROGRAM_MISMATCH = 40
    WITNESS_MALLEATED = 41
    WITNESS_MALLEATED_P2SH = 42
    WITNESS_UNEXPECTED = 43
    WITNESS_PUBKEYTYPE = 44
    # Taproot
    SCHNORR_SIG_SIZE = 45
    SCHNORR_SIG_HASHTYPE = 46
    SCHNORR_SIG = 47
    TAPROOT_WRONG_CONTROL_SIZE = 48
    TAPSCRIPT_VALIDATION_WEIGHT = 49
    TAPSCRIPT_CHECKMULTISIG = 50
    TAPSCRIPT_MINIMALIF = 51
    TAPSCRIPT_EMPTY_PUBKEY = 52
    # Constant scriptCode
    OP_CODESEPARATOR = 53
    SIG_FINDANDDELETE = 54


_OK = ScriptError.OK


# --- interpreter.h --------------------------------------------------------------------

SIGHASH_OUTPUT_MASK = 3
SIGHASH_INPUT_MASK = 0x80


class ScriptFlags(enum.IntFlag):
    """Script verification flags (SCRIPT_VERIFY_*), with Core's bit values."""
    NONE = 0
    P2SH = 1 << 0
    STRICTENC = 1 << 1
    DERSIG = 1 << 2
    LOW_S = 1 << 3
    NULLDUMMY = 1 << 4
    SIGPUSHONLY = 1 << 5
    MINIMALDATA = 1 << 6
    DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
    CLEANSTACK = 1 << 8
    CHECKLOCKTIMEVERIFY = 1 << 9
    CHECKSEQUENCEVERIFY = 1 << 10
    WITNESS = 1 << 11
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12
    MINIMALIF = 1 << 13
    NULLFAIL = 1 << 14
    WITNESS_PUBKEYTYPE = 1 << 15
    CONST_SCRIPTCODE = 1 << 16
    TAPROOT = 1 << 17
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 18
    DISCOURAGE_OP_SUCCESS = 1 << 19
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 20


MAX_SCRIPT_VERIFY_FLAGS_BITS = 21

# plain ints, for speed
SCRIPT_VERIFY_P2SH = 1 << 0
SCRIPT_VERIFY_STRICTENC = 1 << 1
SCRIPT_VERIFY_DERSIG = 1 << 2
SCRIPT_VERIFY_LOW_S = 1 << 3
SCRIPT_VERIFY_NULLDUMMY = 1 << 4
SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5
SCRIPT_VERIFY_MINIMALDATA = 1 << 6
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
SCRIPT_VERIFY_CLEANSTACK = 1 << 8
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10
SCRIPT_VERIFY_WITNESS = 1 << 11
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12
SCRIPT_VERIFY_MINIMALIF = 1 << 13
SCRIPT_VERIFY_NULLFAIL = 1 << 14
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = 1 << 15
SCRIPT_VERIFY_CONST_SCRIPTCODE = 1 << 16
SCRIPT_VERIFY_TAPROOT = 1 << 17
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 18
SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = 1 << 19
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 20

# Core: MANDATORY_SCRIPT_VERIFY_FLAGS (policy/policy.h), every soft fork active at the chain tip
CONSENSUS_FLAGS = (
    ScriptFlags.P2SH | ScriptFlags.DERSIG | ScriptFlags.NULLDUMMY | ScriptFlags.CHECKLOCKTIMEVERIFY
    | ScriptFlags.CHECKSEQUENCEVERIFY | ScriptFlags.WITNESS | ScriptFlags.TAPROOT
)
# Core: STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h)
STANDARD_FLAGS = (
    CONSENSUS_FLAGS | ScriptFlags.STRICTENC | ScriptFlags.MINIMALDATA | ScriptFlags.DISCOURAGE_UPGRADABLE_NOPS
    | ScriptFlags.CLEANSTACK | ScriptFlags.MINIMALIF | ScriptFlags.NULLFAIL | ScriptFlags.LOW_S
    | ScriptFlags.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | ScriptFlags.WITNESS_PUBKEYTYPE
    | ScriptFlags.CONST_SCRIPTCODE | ScriptFlags.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    | ScriptFlags.DISCOURAGE_OP_SUCCESS | ScriptFlags.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
)


def is_valid_flag_combination(flags: int) -> bool:
    """Flag combinations that Core asserts on in VerifyScript are rejected."""
    if flags & SCRIPT_VERIFY_CLEANSTACK and not flags & SCRIPT_VERIFY_WITNESS:
        return False
    if flags & SCRIPT_VERIFY_WITNESS and not flags & SCRIPT_VERIFY_P2SH:
        return False
    return True


class SigVersion(enum.IntEnum):
    BASE = 0          # Bare scripts and BIP16 P2SH-wrapped redeemscripts
    WITNESS_V0 = 1    # Witness v0 (P2WPKH and P2WSH); see BIP 141
    TAPROOT = 2       # Witness v1 with 32-byte program, not BIP16 P2SH-wrapped, key path spending
    TAPSCRIPT = 3     # Witness v1 with 32-byte program, not BIP16 P2SH-wrapped, script path, leaf 0xc0


WITNESS_V0_SCRIPTHASH_SIZE = 32
WITNESS_V0_KEYHASH_SIZE = 20
WITNESS_V1_TAPROOT_SIZE = 32

TAPROOT_LEAF_MASK = 0xfe
TAPROOT_LEAF_TAPSCRIPT = 0xc0
TAPROOT_CONTROL_BASE_SIZE = 33
TAPROOT_CONTROL_NODE_SIZE = 32
TAPROOT_CONTROL_MAX_NODE_COUNT = 128
TAPROOT_CONTROL_MAX_SIZE = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT


# --- exceptions and resource limits ---------------------------------------------------

class ScriptVerificationError(Exception):
    """An input's scriptSig/witness does not satisfy the scriptPubKey it spends."""

    def __init__(self, error: ScriptError, txin_index: int):
        super().__init__(f"input {txin_index}: script verification failed: {error.name}")
        self.error = error
        self.txin_index = txin_index


class TxValidationError(Exception):
    """Context-free or value consensus failure. .reason is Core's reject reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ResourceLimitExceeded(Exception):
    """The VerificationBudget was exhausted. This is NOT proof that the tx is invalid."""


class VerificationBudget:
    """Bounds the work done by verify_input/verify_transaction on untrusted data.

    max_sig_checks: number of ECDSA/Schnorr signature verifications (plus taproot
      commitment checks, which cost about the same).
    max_sighash_bytes: number of bytes hashed for legacy and BIP143 signature hashes.
      Legacy sighashes also need Python-level walks over the scriptCode (OP_CODESEPARATOR
      removal, FindAndDelete); these are charged at SCRIPT_WALK_COST bytes per script byte.

    Opcode execution and sigop counting are not metered. Their cost is linear in the size of
    the tx and its spent scriptPubKeys, so callers bound it by bounding those sizes.

    A budget can be shared between several calls; its counters keep accumulating.
    """
    SCRIPT_WALK_COST = 64

    def __init__(self, *, max_sig_checks: int, max_sighash_bytes: int):
        self.max_sig_checks = max_sig_checks
        self.max_sighash_bytes = max_sighash_bytes
        self.sig_checks = 0
        self.sighash_bytes = 0

    def charge_sig_check(self) -> None:
        self.sig_checks += 1
        if self.sig_checks > self.max_sig_checks:
            raise ResourceLimitExceeded(f"more than {self.max_sig_checks} signature checks")

    def charge_sighash_bytes(self, n: int) -> None:
        self.sighash_bytes += n
        if self.sighash_bytes > self.max_sighash_bytes:
            raise ResourceLimitExceeded(f"more than {self.max_sighash_bytes} sighash bytes")

    def charge_script_walk(self, script_len: int) -> None:
        self.charge_sighash_bytes(script_len * self.SCRIPT_WALK_COST)


# --- interpreter.cpp ------------------------------------------------------------------

def CastToBool(vch: bytes) -> bool:
    if not vch:
        return False
    if any(vch[:-1]):
        return True
    # Can be negative zero
    return (vch[-1] & 0x7f) != 0


def IsCompressedOrUncompressedPubKey(pubkey: bytes) -> bool:
    if len(pubkey) < 33:
        #  Non-canonical public key: too short
        return False
    if pubkey[0] == 0x04:
        if len(pubkey) != 65:
            #  Non-canonical public key: invalid length for uncompressed key
            return False
    elif pubkey[0] == 0x02 or pubkey[0] == 0x03:
        if len(pubkey) != 33:
            #  Non-canonical public key: invalid length for compressed key
            return False
    else:
        #  Non-canonical public key: neither compressed nor uncompressed
        return False
    return True


def IsCompressedPubKey(pubkey: bytes) -> bool:
    if len(pubkey) != 33:
        #  Non-canonical public key: invalid length for compressed key
        return False
    if pubkey[0] != 0x02 and pubkey[0] != 0x03:
        #  Non-canonical public key: invalid prefix for compressed key
        return False
    return True


def IsValidSignatureEncoding(sig: bytes) -> bool:
    """A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
    Where R and S are not negative (their first byte has its highest bit not set), and not
    excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
    in which case a single 0 byte is necessary and even required).

    This function is consensus-critical since BIP66.
    """
    # Minimum and maximum size constraints.
    if len(sig) < 9:
        return False
    if len(sig) > 73:
        return False
    # A signature is of type 0x30 (compound).
    if sig[0] != 0x30:
        return False
    # Make sure the length covers the entire signature.
    if sig[1] != len(sig) - 3:
        return False
    # Extract the length of the R element.
    len_r = sig[3]
    # Make sure the length of the S element is still inside the signature.
    if 5 + len_r >= len(sig):
        return False
    # Extract the length of the S element.
    len_s = sig[5 + len_r]
    # Verify that the length of the signature matches the sum of the length of the elements.
    if len_r + len_s + 7 != len(sig):
        return False
    # Check whether the R element is an integer.
    if sig[2] != 0x02:
        return False
    # Zero-length integers are not allowed for R.
    if len_r == 0:
        return False
    # Negative numbers are not allowed for R.
    if sig[4] & 0x80:
        return False
    # Null bytes at the start of R are not allowed, unless R would otherwise be interpreted
    # as a negative number.
    if len_r > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
        return False
    # Check whether the S element is an integer.
    if sig[len_r + 4] != 0x02:
        return False
    # Zero-length integers are not allowed for S.
    if len_s == 0:
        return False
    # Negative numbers are not allowed for S.
    if sig[len_r + 6] & 0x80:
        return False
    # Null bytes at the start of S are not allowed, unless S would otherwise be interpreted
    # as a negative number.
    if len_s > 1 and sig[len_r + 6] == 0x00 and not (sig[len_r + 7] & 0x80):
        return False
    return True


def ecdsa_signature_parse_der_lax(sig: bytes) -> Optional[bytes]:
    """Port of pubkey.cpp's ecdsa_signature_parse_der_lax (BER-tolerant DER parsing).
    Returns the 64-byte compact r||s, or None if parsing fails. Like Core (via
    secp256k1_ecdsa_signature_parse_compact), an R or S that overflows yields the
    all-zero signature, which never verifies.
    """
    inputlen = len(sig)
    pos = 0
    # Sequence tag byte
    if pos == inputlen or sig[pos] != 0x30:
        return None
    pos += 1
    # Sequence length bytes
    if pos == inputlen:
        return None
    lenbyte = sig[pos]
    pos += 1
    if lenbyte & 0x80:
        lenbyte -= 0x80
        if lenbyte > inputlen - pos:
            return None
        pos += lenbyte
    # Integer tag byte for R
    if pos == inputlen or sig[pos] != 0x02:
        return None
    pos += 1
    # Integer length for R
    if pos == inputlen:
        return None
    lenbyte = sig[pos]
    pos += 1
    if lenbyte & 0x80:
        lenbyte -= 0x80
        if lenbyte > inputlen - pos:
            return None
        while lenbyte > 0 and sig[pos] == 0:
            pos += 1
            lenbyte -= 1
        if lenbyte >= 4:
            return None
        rlen = 0
        while lenbyte > 0:
            rlen = (rlen << 8) + sig[pos]
            pos += 1
            lenbyte -= 1
    else:
        rlen = lenbyte
    if rlen > inputlen - pos:
        return None
    rpos = pos
    pos += rlen
    # Integer tag byte for S
    if pos == inputlen or sig[pos] != 0x02:
        return None
    pos += 1
    # Integer length for S
    if pos == inputlen:
        return None
    lenbyte = sig[pos]
    pos += 1
    if lenbyte & 0x80:
        lenbyte -= 0x80
        if lenbyte > inputlen - pos:
            return None
        while lenbyte > 0 and sig[pos] == 0:
            pos += 1
            lenbyte -= 1
        if lenbyte >= 4:
            return None
        slen = 0
        while lenbyte > 0:
            slen = (slen << 8) + sig[pos]
            pos += 1
            lenbyte -= 1
    else:
        slen = lenbyte
    if slen > inputlen - pos:
        return None
    spos = pos
    # Ignore leading zeroes in R
    while rlen > 0 and sig[rpos] == 0:
        rlen -= 1
        rpos += 1
    # Ignore leading zeroes in S
    while slen > 0 and sig[spos] == 0:
        slen -= 1
        spos += 1
    if rlen > 32 or slen > 32:
        return bytes(64)
    r = int.from_bytes(sig[rpos:rpos + rlen], 'big')
    s = int.from_bytes(sig[spos:spos + slen], 'big')
    if r >= ecc.CURVE_ORDER or s >= ecc.CURVE_ORDER:
        return bytes(64)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def CheckLowS(sig: bytes) -> bool:
    """Core: CPubKey::CheckLowS. sig is DER without the hashtype byte."""
    compact = ecdsa_signature_parse_der_lax(sig)
    if compact is None:
        return False
    return int.from_bytes(compact[32:], 'big') <= ecc.CURVE_ORDER // 2


def IsLowDERSignature(sig: bytes) -> ScriptError:
    if not IsValidSignatureEncoding(sig):
        return ScriptError.SIG_DER
    # If the S value is above the order of the curve divided by two, its complement modulo
    # the order could have been used instead, which is one byte shorter when encoded correctly.
    if not CheckLowS(sig[:-1]):
        return ScriptError.SIG_HIGH_S
    return _OK


def IsDefinedHashtypeSignature(sig: bytes) -> bool:
    return len(sig) > 0 and Sighash.is_valid(sig[-1])


def CheckSignatureEncoding(sig: bytes, flags: int) -> ScriptError:
    # Empty signature. Not strictly DER encoded, but allowed to provide a
    # compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if len(sig) == 0:
        return _OK
    if (flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) and not IsValidSignatureEncoding(sig):
        return ScriptError.SIG_DER
    elif flags & SCRIPT_VERIFY_LOW_S:
        err = IsLowDERSignature(sig)
        if err is not _OK:
            return err
    if flags & SCRIPT_VERIFY_STRICTENC and not IsDefinedHashtypeSignature(sig):
        return ScriptError.SIG_HASHTYPE
    return _OK


def CheckPubKeyEncoding(pubkey: bytes, flags: int, sigversion: SigVersion) -> ScriptError:
    if flags & SCRIPT_VERIFY_STRICTENC and not IsCompressedOrUncompressedPubKey(pubkey):
        return ScriptError.PUBKEYTYPE
    # Only compressed keys are accepted in segwit
    if flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE and sigversion == SigVersion.WITNESS_V0 and not IsCompressedPubKey(pubkey):
        return ScriptError.WITNESS_PUBKEYTYPE
    return _OK


def FindAndDelete(script: bytes, b: bytes, *, budget: 'VerificationBudget' = None) -> Tuple[bytes, int]:
    """Returns (new_script, number_of_matches)."""
    if not b:
        return script, 0
    if b not in script:
        # Core: shortcut, a match at an op boundary is impossible.
        return script, 0
    if budget is not None:
        budget.charge_script_walk(len(script))
    n_found = 0
    result = []
    pc = pc2 = 0
    end = len(script)
    blen = len(b)
    while True:
        result.append(script[pc2:pc])
        while end - pc >= blen and script.startswith(b, pc):
            pc += blen
            n_found += 1
        pc2 = pc
        if pc >= end:
            break
        pc = _next_op(script, pc, end)
        if pc < 0:
            break
    if n_found > 0:
        result.append(script[pc2:end])
        return b''.join(result), n_found
    return script, 0


class ConditionStack:
    """A data type to abstract out the condition stack during script execution.

    Conceptually it acts like a vector of booleans, one for each level of nested
    IF/THEN/ELSE, indicating whether we're in the active or inactive branch of each.
    Only the size of the would-be stack and the position of its first false value are stored.
    """
    NO_FALSE = -1

    __slots__ = ('stack_size', 'first_false_pos')

    def __init__(self):
        self.stack_size = 0
        self.first_false_pos = self.NO_FALSE

    def empty(self) -> bool:
        return self.stack_size == 0

    def all_true(self) -> bool:
        return self.first_false_pos == self.NO_FALSE

    def push_back(self, f: bool) -> None:
        if self.first_false_pos == self.NO_FALSE and not f:
            # The stack consists of all true values, and a false is added.
            # The first false value will appear at the current size.
            self.first_false_pos = self.stack_size
        self.stack_size += 1

    def pop_back(self) -> None:
        assert self.stack_size > 0
        self.stack_size -= 1
        if self.first_false_pos == self.stack_size:
            # When popping off the first false value, everything becomes true.
            self.first_false_pos = self.NO_FALSE

    def toggle_top(self) -> None:
        assert self.stack_size > 0
        if self.first_false_pos == self.NO_FALSE:
            # The current stack is all true values; the first false will be the top.
            self.first_false_pos = self.stack_size - 1
        elif self.first_false_pos == self.stack_size - 1:
            # The top is the first false value; toggling it will make everything true.
            self.first_false_pos = self.NO_FALSE
        else:
            # There is a false value, but not on top. No action is needed as toggling
            # anything but the first false value is unobservable.
            pass


class ScriptExecutionData:
    """None means 'not initialized' (Core: the m_*_init booleans)."""
    __slots__ = ('tapleaf_hash', 'codeseparator_pos', 'annex_present', 'annex_hash',
                 'validation_weight_left', 'output_hash')

    def __init__(self):
        self.tapleaf_hash = None  # type: Optional[bytes]
        # Opcode position of the last executed OP_CODESEPARATOR (or 0xFFFFFFFF if none executed).
        self.codeseparator_pos = None  # type: Optional[int]
        self.annex_present = None  # type: Optional[bool]
        self.annex_hash = None  # type: Optional[bytes]
        # How much validation weight is left (decremented for every successful non-empty signature check).
        self.validation_weight_left = None  # type: Optional[int]
        # The hash of the corresponding output
        self.output_hash = None  # type: Optional[bytes]


def EvalChecksigPreTapscript(sig: bytes, pubkey: bytes, script: bytes, pbegincodehash: int, flags: int,
                             checker: 'BaseSignatureChecker', sigversion: SigVersion) -> Tuple[ScriptError, bool]:
    """Returns (error, success)."""
    assert sigversion == SigVersion.BASE or sigversion == SigVersion.WITNESS_V0
    # Subset of script starting at the most recent codeseparator
    script_code = script[pbegincodehash:]
    # Drop the signature in pre-segwit scripts but not segwit scripts
    if sigversion == SigVersion.BASE:
        script_code, found = FindAndDelete(script_code, _push_data(sig), budget=checker.budget)
        if found > 0 and flags & SCRIPT_VERIFY_CONST_SCRIPTCODE:
            return ScriptError.SIG_FINDANDDELETE, False
    err = CheckSignatureEncoding(sig, flags)
    if err is not _OK:
        return err, False
    err = CheckPubKeyEncoding(pubkey, flags, sigversion)
    if err is not _OK:
        return err, False
    success = checker.CheckECDSASignature(sig, pubkey, script_code, sigversion)
    if not success and flags & SCRIPT_VERIFY_NULLFAIL and len(sig):
        return ScriptError.NULLFAIL, False
    return _OK, success


def EvalChecksigTapscript(sig: bytes, pubkey: bytes, execdata: ScriptExecutionData, flags: int,
                          checker: 'BaseSignatureChecker', sigversion: SigVersion) -> Tuple[ScriptError, bool]:
    assert sigversion == SigVersion.TAPSCRIPT
    # The following validation sequence is consensus critical. Please note how --
    #   upgradable public key versions precede other rules;
    #   the script execution fails when using empty signature with invalid public key;
    #   the script execution fails when using non-empty invalid signature.
    success = len(sig) != 0
    if success:
        # Implement the sigops/witnesssize ratio test.
        # Passing with an upgradable public key version is also counted.
        assert execdata.validation_weight_left is not None
        execdata.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED
        if execdata.validation_weight_left < 0:
            return ScriptError.TAPSCRIPT_VALIDATION_WEIGHT, False
    if len(pubkey) == 0:
        return ScriptError.TAPSCRIPT_EMPTY_PUBKEY, False
    elif len(pubkey) == 32:
        if success:
            err = checker.CheckSchnorrSignature(sig, pubkey, sigversion, execdata)
            if err is not _OK:
                return err, False
    else:
        # New public key version softforks should be defined before this `else` block.
        if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
            return ScriptError.DISCOURAGE_UPGRADABLE_PUBKEYTYPE, False
    return _OK, success


def EvalChecksig(sig: bytes, pubkey: bytes, script: bytes, pbegincodehash: int, execdata: ScriptExecutionData,
                 flags: int, checker: 'BaseSignatureChecker', sigversion: SigVersion) -> Tuple[ScriptError, bool]:
    """Helper for OP_CHECKSIG, OP_CHECKSIGVERIFY, and (in Tapscript) OP_CHECKSIGADD.
    A non-OK error means the script fails entirely. Otherwise, success indicates whether
    the signature check itself succeeded.
    """
    if sigversion == SigVersion.BASE or sigversion == SigVersion.WITNESS_V0:
        return EvalChecksigPreTapscript(sig, pubkey, script, pbegincodehash, flags, checker, sigversion)
    elif sigversion == SigVersion.TAPSCRIPT:
        return EvalChecksigTapscript(sig, pubkey, execdata, flags, checker, sigversion)
    # Key path spending in Taproot has no script, so this is unreachable.
    raise AssertionError("unreachable")


_VCH_FALSE = b''
_VCH_TRUE = b'\x01'
_SMALL_INT_PUSH = tuple(script_num_to_bytes(i - (opcodes.OP_1 - 1)) if opcodes.OP_1NEGATE <= i <= opcodes.OP_16 else None
                        for i in range(256))


def EvalScript(stack: List[bytes], script: bytes, flags: int, checker: 'BaseSignatureChecker',
               sigversion: SigVersion, execdata: ScriptExecutionData = None) -> ScriptError:
    flags = int(flags)
    if execdata is None:
        execdata = ScriptExecutionData()
    # sigversion cannot be TAPROOT here, as it admits no script execution.
    assert sigversion in (SigVersion.BASE, SigVersion.WITNESS_V0, SigVersion.TAPSCRIPT)
    pre_tapscript = sigversion != SigVersion.TAPSCRIPT

    pc = 0
    pend = len(script)
    pbegincodehash = 0
    vf_exec = ConditionStack()
    altstack = []  # type: List[bytes]
    if pre_tapscript and pend > MAX_SCRIPT_SIZE:
        return ScriptError.SCRIPT_SIZE
    n_op_count = 0
    require_minimal = bool(flags & SCRIPT_VERIFY_MINIMALDATA)
    opcode_pos = -1  # Core: incremented at the end of each loop iteration, starting at 0
    execdata.codeseparator_pos = 0xFFFFFFFF

    try:
        while pc < pend:
            opcode_pos += 1
            f_exec = vf_exec.first_false_pos == ConditionStack.NO_FALSE  # all_true()

            # Read instruction (Core: GetOp, inlined)
            opcode = script[pc]
            pc += 1
            push_value = b''
            if opcode <= opcodes.OP_PUSHDATA4:
                if opcode < opcodes.OP_PUSHDATA1:
                    n_size = opcode
                elif opcode == opcodes.OP_PUSHDATA1:
                    if pend - pc < 1:
                        return ScriptError.BAD_OPCODE
                    n_size = script[pc]
                    pc += 1
                elif opcode == opcodes.OP_PUSHDATA2:
                    if pend - pc < 2:
                        return ScriptError.BAD_OPCODE
                    n_size = script[pc] | (script[pc + 1] << 8)
                    pc += 2
                else:
                    if pend - pc < 4:
                        return ScriptError.BAD_OPCODE
                    n_size = int.from_bytes(script[pc:pc + 4], 'little')
                    pc += 4
                if pend - pc < n_size:
                    return ScriptError.BAD_OPCODE
                if n_size > MAX_SCRIPT_ELEMENT_SIZE:
                    return ScriptError.PUSH_SIZE
                push_value = script[pc:pc + n_size]
                pc += n_size

            if pre_tapscript:
                # Note how OP_RESERVED does not count towards the opcode limit.
                if opcode > opcodes.OP_16:
                    n_op_count += 1
                    if n_op_count > MAX_OPS_PER_SCRIPT:
                        return ScriptError.OP_COUNT

            if opcode in _DISABLED_OPCODES:
                return ScriptError.DISABLED_OPCODE  # Disabled opcodes (CVE-2010-5137).

            # With SCRIPT_VERIFY_CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script is rejected even in an unexecuted branch
            if opcode == opcodes.OP_CODESEPARATOR and sigversion == SigVersion.BASE and flags & SCRIPT_VERIFY_CONST_SCRIPTCODE:
                return ScriptError.OP_CODESEPARATOR

            if f_exec and opcode <= opcodes.OP_PUSHDATA4:
                if require_minimal and not CheckMinimalPush(push_value, opcode):
                    return ScriptError.MINIMALDATA
                stack.append(push_value)
            elif f_exec or (opcodes.OP_IF <= opcode <= opcodes.OP_ENDIF):
                #
                # Push value
                #
                if opcodes.OP_1NEGATE <= opcode <= opcodes.OP_16 and opcode != opcodes.OP_RESERVED:
                    # ( -- value)
                    stack.append(_SMALL_INT_PUSH[opcode])

                #
                # Control
                #
                elif opcode == opcodes.OP_NOP:
                    pass

                elif opcode == opcodes.OP_CHECKLOCKTIMEVERIFY:
                    if flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY:
                        if len(stack) < 1:
                            return ScriptError.INVALID_STACK_OPERATION
                        # Note that elsewhere numeric opcodes are limited to operands in the range
                        # -2**31+1 to 2**31-1, however it is legal for opcodes to produce results
                        # exceeding that range. As a special case we accept up to 5-byte bignums here.
                        n_lock_time = CScriptNum(stack[-1], require_minimal, 5)
                        # In the rare event that the argument may be < 0 due to some arithmetic
                        # being done first, you can always use 0 MAX CHECKLOCKTIMEVERIFY.
                        if n_lock_time < 0:
                            return ScriptError.NEGATIVE_LOCKTIME
                        # Actually compare the specified lock time with the transaction.
                        if not checker.CheckLockTime(n_lock_time):
                            return ScriptError.UNSATISFIED_LOCKTIME
                    # else: not enabled; treat as a NOP2

                elif opcode == opcodes.OP_CHECKSEQUENCEVERIFY:
                    if flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY:
                        if len(stack) < 1:
                            return ScriptError.INVALID_STACK_OPERATION
                        # nSequence, like nLockTime, is a 32-bit unsigned integer field.
                        # See the comment in CHECKLOCKTIMEVERIFY regarding 5-byte numeric operands.
                        n_sequence = CScriptNum(stack[-1], require_minimal, 5)
                        # In the rare event that the argument may be < 0 due to some arithmetic
                        # being done first, you can always use 0 MAX CHECKSEQUENCEVERIFY.
                        if n_sequence < 0:
                            return ScriptError.NEGATIVE_LOCKTIME
                        # To provide for future soft-fork extensibility, if the operand has the
                        # disabled lock-time flag set, CHECKSEQUENCEVERIFY behaves as a NOP.
                        if not (n_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG):
                            # Compare the specified sequence number with the input.
                            if not checker.CheckSequence(n_sequence):
                                return ScriptError.UNSATISFIED_LOCKTIME
                    # else: not enabled; treat as a NOP3

                elif opcode in _UPGRADABLE_NOPS:
                    if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS:
                        return ScriptError.DISCOURAGE_UPGRADABLE_NOPS

                elif opcode == opcodes.OP_IF or opcode == opcodes.OP_NOTIF:
                    # <expression> if [statements] [else [statements]] endif
                    f_value = False
                    if f_exec:
                        if len(stack) < 1:
                            return ScriptError.INVALID_STACK_OPERATION
                        vch = stack[-1]
                        # Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                        if sigversion == SigVersion.TAPSCRIPT:
                            # The input argument to the OP_IF and OP_NOTIF opcodes must be either
                            # exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                            if len(vch) > 1 or (len(vch) == 1 and vch[0] != 1):
                                return ScriptError.TAPSCRIPT_MINIMALIF
                        # Under witness v0 rules it is only a policy rule, enabled through SCRIPT_VERIFY_MINIMALIF.
                        if sigversion == SigVersion.WITNESS_V0 and flags & SCRIPT_VERIFY_MINIMALIF:
                            if len(vch) > 1:
                                return ScriptError.MINIMALIF
                            if len(vch) == 1 and vch[0] != 1:
                                return ScriptError.MINIMALIF
                        f_value = CastToBool(vch)
                        if opcode == opcodes.OP_NOTIF:
                            f_value = not f_value
                        stack.pop()
                    vf_exec.push_back(f_value)

                elif opcode == opcodes.OP_ELSE:
                    if vf_exec.empty():
                        return ScriptError.UNBALANCED_CONDITIONAL
                    vf_exec.toggle_top()

                elif opcode == opcodes.OP_ENDIF:
                    if vf_exec.empty():
                        return ScriptError.UNBALANCED_CONDITIONAL
                    vf_exec.pop_back()

                elif opcode == opcodes.OP_VERIFY:
                    # (true -- ) or
                    # (false -- false) and return
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    if CastToBool(stack[-1]):
                        stack.pop()
                    else:
                        return ScriptError.VERIFY

                elif opcode == opcodes.OP_RETURN:
                    return ScriptError.OP_RETURN

                #
                # Stack ops
                #
                elif opcode == opcodes.OP_TOALTSTACK:
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    altstack.append(stack.pop())

                elif opcode == opcodes.OP_FROMALTSTACK:
                    if len(altstack) < 1:
                        return ScriptError.INVALID_ALTSTACK_OPERATION
                    stack.append(altstack.pop())

                elif opcode == opcodes.OP_2DROP:
                    # (x1 x2 -- )
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.pop()
                    stack.pop()

                elif opcode == opcodes.OP_2DUP:
                    # (x1 x2 -- x1 x2 x1 x2)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.extend(stack[-2:])

                elif opcode == opcodes.OP_3DUP:
                    # (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if len(stack) < 3:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.extend(stack[-3:])

                elif opcode == opcodes.OP_2OVER:
                    # (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if len(stack) < 4:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.extend(stack[-4:-2])

                elif opcode == opcodes.OP_2ROT:
                    # (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if len(stack) < 6:
                        return ScriptError.INVALID_STACK_OPERATION
                    vch12 = stack[-6:-4]
                    del stack[-6:-4]
                    stack.extend(vch12)

                elif opcode == opcodes.OP_2SWAP:
                    # (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if len(stack) < 4:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack[-4], stack[-2] = stack[-2], stack[-4]
                    stack[-3], stack[-1] = stack[-1], stack[-3]

                elif opcode == opcodes.OP_IFDUP:
                    # (x - 0 | x x)
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    vch = stack[-1]
                    if CastToBool(vch):
                        stack.append(vch)

                elif opcode == opcodes.OP_DEPTH:
                    # -- stacksize
                    stack.append(script_num_to_bytes(len(stack)))

                elif opcode == opcodes.OP_DROP:
                    # (x -- )
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.pop()

                elif opcode == opcodes.OP_DUP:
                    # (x -- x x)
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.append(stack[-1])

                elif opcode == opcodes.OP_NIP:
                    # (x1 x2 -- x2)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    del stack[-2]

                elif opcode == opcodes.OP_OVER:
                    # (x1 x2 -- x1 x2 x1)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.append(stack[-2])

                elif opcode == opcodes.OP_PICK or opcode == opcodes.OP_ROLL:
                    # (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    # (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    n = _getint(CScriptNum(stack[-1], require_minimal))
                    stack.pop()
                    if n < 0 or n >= len(stack):
                        return ScriptError.INVALID_STACK_OPERATION
                    vch = stack[-n - 1]
                    if opcode == opcodes.OP_ROLL:
                        del stack[-n - 1]
                    stack.append(vch)

                elif opcode == opcodes.OP_ROT:
                    # (x1 x2 x3 -- x2 x3 x1)
                    if len(stack) < 3:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-3]

                elif opcode == opcodes.OP_SWAP:
                    # (x1 x2 -- x2 x1)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack[-2], stack[-1] = stack[-1], stack[-2]

                elif opcode == opcodes.OP_TUCK:
                    # (x1 x2 -- x2 x1 x2)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.insert(len(stack) - 2, stack[-1])

                elif opcode == opcodes.OP_SIZE:
                    # (in -- in size)
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    stack.append(script_num_to_bytes(len(stack[-1])))

                #
                # Bitwise logic
                #
                elif opcode == opcodes.OP_EQUAL or opcode == opcodes.OP_EQUALVERIFY:
                    # (x1 x2 - bool)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    f_equal = stack[-2] == stack[-1]
                    stack.pop()
                    stack.pop()
                    stack.append(_VCH_TRUE if f_equal else _VCH_FALSE)
                    if opcode == opcodes.OP_EQUALVERIFY:
                        if f_equal:
                            stack.pop()
                        else:
                            return ScriptError.EQUALVERIFY

                #
                # Numeric
                #
                elif opcodes.OP_1ADD <= opcode <= opcodes.OP_0NOTEQUAL:  # (OP_2MUL, OP_2DIV are disabled)
                    # (in -- out)
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    bn = CScriptNum(stack[-1], require_minimal)
                    if opcode == opcodes.OP_1ADD:
                        bn += 1
                    elif opcode == opcodes.OP_1SUB:
                        bn -= 1
                    elif opcode == opcodes.OP_NEGATE:
                        bn = -bn
                    elif opcode == opcodes.OP_ABS:
                        if bn < 0:
                            bn = -bn
                    elif opcode == opcodes.OP_NOT:
                        bn = int(bn == 0)
                    elif opcode == opcodes.OP_0NOTEQUAL:
                        bn = int(bn != 0)
                    else:
                        raise AssertionError("invalid opcode")
                    stack.pop()
                    stack.append(script_num_to_bytes(bn))

                elif opcodes.OP_ADD <= opcode <= opcodes.OP_MAX:  # (OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT are disabled)
                    # (x1 x2 -- out)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    bn1 = CScriptNum(stack[-2], require_minimal)
                    bn2 = CScriptNum(stack[-1], require_minimal)
                    if opcode == opcodes.OP_ADD:
                        bn = bn1 + bn2
                    elif opcode == opcodes.OP_SUB:
                        bn = bn1 - bn2
                    elif opcode == opcodes.OP_BOOLAND:
                        bn = int(bn1 != 0 and bn2 != 0)
                    elif opcode == opcodes.OP_BOOLOR:
                        bn = int(bn1 != 0 or bn2 != 0)
                    elif opcode == opcodes.OP_NUMEQUAL or opcode == opcodes.OP_NUMEQUALVERIFY:
                        bn = int(bn1 == bn2)
                    elif opcode == opcodes.OP_NUMNOTEQUAL:
                        bn = int(bn1 != bn2)
                    elif opcode == opcodes.OP_LESSTHAN:
                        bn = int(bn1 < bn2)
                    elif opcode == opcodes.OP_GREATERTHAN:
                        bn = int(bn1 > bn2)
                    elif opcode == opcodes.OP_LESSTHANOREQUAL:
                        bn = int(bn1 <= bn2)
                    elif opcode == opcodes.OP_GREATERTHANOREQUAL:
                        bn = int(bn1 >= bn2)
                    elif opcode == opcodes.OP_MIN:
                        bn = bn1 if bn1 < bn2 else bn2
                    elif opcode == opcodes.OP_MAX:
                        bn = bn1 if bn1 > bn2 else bn2
                    else:
                        raise AssertionError("invalid opcode")
                    stack.pop()
                    stack.pop()
                    stack.append(script_num_to_bytes(bn))
                    if opcode == opcodes.OP_NUMEQUALVERIFY:
                        if CastToBool(stack[-1]):
                            stack.pop()
                        else:
                            return ScriptError.NUMEQUALVERIFY

                elif opcode == opcodes.OP_WITHIN:
                    # (x min max -- out)
                    if len(stack) < 3:
                        return ScriptError.INVALID_STACK_OPERATION
                    bn1 = CScriptNum(stack[-3], require_minimal)
                    bn2 = CScriptNum(stack[-2], require_minimal)
                    bn3 = CScriptNum(stack[-1], require_minimal)
                    f_value = bn2 <= bn1 < bn3
                    del stack[-3:]
                    stack.append(_VCH_TRUE if f_value else _VCH_FALSE)

                #
                # Crypto
                #
                elif opcodes.OP_RIPEMD160 <= opcode <= opcodes.OP_HASH256:
                    # (in -- hash)
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    vch = stack[-1]
                    if opcode == opcodes.OP_RIPEMD160:
                        vch_hash = ripemd(vch)
                    elif opcode == opcodes.OP_SHA1:
                        vch_hash = hashlib.sha1(vch).digest()
                    elif opcode == opcodes.OP_SHA256:
                        vch_hash = sha256(vch)
                    elif opcode == opcodes.OP_HASH160:
                        vch_hash = hash_160(vch)
                    else:
                        vch_hash = sha256d(vch)
                    stack[-1] = vch_hash

                elif opcode == opcodes.OP_CODESEPARATOR:
                    # If SCRIPT_VERIFY_CONST_SCRIPTCODE flag is set, use of OP_CODESEPARATOR is rejected in pre-segwit
                    # script, even in an unexecuted branch (this is checked above the opcode case statement).

                    # Hash starts after the code separator
                    pbegincodehash = pc
                    execdata.codeseparator_pos = opcode_pos

                elif opcode == opcodes.OP_CHECKSIG or opcode == opcodes.OP_CHECKSIGVERIFY:
                    # (sig pubkey -- bool)
                    if len(stack) < 2:
                        return ScriptError.INVALID_STACK_OPERATION
                    err, f_success = EvalChecksig(stack[-2], stack[-1], script, pbegincodehash, execdata,
                                                  flags, checker, sigversion)
                    if err is not _OK:
                        return err
                    stack.pop()
                    stack.pop()
                    stack.append(_VCH_TRUE if f_success else _VCH_FALSE)
                    if opcode == opcodes.OP_CHECKSIGVERIFY:
                        if f_success:
                            stack.pop()
                        else:
                            return ScriptError.CHECKSIGVERIFY

                elif opcode == opcodes.OP_CHECKSIGADD:
                    # OP_CHECKSIGADD is only available in Tapscript
                    if pre_tapscript:
                        return ScriptError.BAD_OPCODE
                    # (sig num pubkey -- num)
                    if len(stack) < 3:
                        return ScriptError.INVALID_STACK_OPERATION
                    sig = stack[-3]
                    num = CScriptNum(stack[-2], require_minimal)
                    pubkey = stack[-1]
                    err, success = EvalChecksig(sig, pubkey, script, pbegincodehash, execdata,
                                                flags, checker, sigversion)
                    if err is not _OK:
                        return err
                    del stack[-3:]
                    stack.append(script_num_to_bytes(num + (1 if success else 0)))

                elif opcode == opcodes.OP_CHECKMULTISIG or opcode == opcodes.OP_CHECKMULTISIGVERIFY:
                    if sigversion == SigVersion.TAPSCRIPT:
                        return ScriptError.TAPSCRIPT_CHECKMULTISIG

                    # ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
                    i = 1
                    if len(stack) < i:
                        return ScriptError.INVALID_STACK_OPERATION

                    n_keys_count = _getint(CScriptNum(stack[-i], require_minimal))
                    if n_keys_count < 0 or n_keys_count > MAX_PUBKEYS_PER_MULTISIG:
                        return ScriptError.PUBKEY_COUNT
                    n_op_count += n_keys_count
                    if n_op_count > MAX_OPS_PER_SCRIPT:
                        return ScriptError.OP_COUNT
                    i += 1
                    ikey = i
                    # ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                    # With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                    ikey2 = n_keys_count + 2
                    i += n_keys_count
                    if len(stack) < i:
                        return ScriptError.INVALID_STACK_OPERATION

                    n_sigs_count = _getint(CScriptNum(stack[-i], require_minimal))
                    if n_sigs_count < 0 or n_sigs_count > n_keys_count:
                        return ScriptError.SIG_COUNT
                    i += 1
                    isig = i
                    i += n_sigs_count
                    if len(stack) < i:
                        return ScriptError.INVALID_STACK_OPERATION

                    # Subset of script starting at the most recent codeseparator
                    script_code = script[pbegincodehash:]

                    # Drop the signature in pre-segwit scripts but not segwit scripts
                    for k in range(n_sigs_count):
                        vch_sig = stack[-isig - k]
                        if sigversion == SigVersion.BASE:
                            script_code, found = FindAndDelete(script_code, _push_data(vch_sig), budget=checker.budget)
                            if found > 0 and flags & SCRIPT_VERIFY_CONST_SCRIPTCODE:
                                return ScriptError.SIG_FINDANDDELETE

                    f_success = True
                    while f_success and n_sigs_count > 0:
                        vch_sig = stack[-isig]
                        vch_pubkey = stack[-ikey]

                        # Note how this makes the exact order of pubkey/signature evaluation
                        # distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                        err = CheckSignatureEncoding(vch_sig, flags)
                        if err is not _OK:
                            return err
                        err = CheckPubKeyEncoding(vch_pubkey, flags, sigversion)
                        if err is not _OK:
                            return err

                        # Check signature
                        f_ok = checker.CheckECDSASignature(vch_sig, vch_pubkey, script_code, sigversion)

                        if f_ok:
                            isig += 1
                            n_sigs_count -= 1
                        ikey += 1
                        n_keys_count -= 1

                        # If there are more signatures left than keys left,
                        # then too many signatures have failed. Exit early,
                        # without checking any further signatures.
                        if n_sigs_count > n_keys_count:
                            f_success = False

                    # Clean up stack of actual arguments
                    while i > 1:  # Core: while (i-- > 1)
                        i -= 1
                        # If the operation failed, we require that all signatures must be empty vector
                        if not f_success and flags & SCRIPT_VERIFY_NULLFAIL and not ikey2 and len(stack[-1]):
                            return ScriptError.NULLFAIL
                        if ikey2 > 0:
                            ikey2 -= 1
                        stack.pop()

                    # A bug causes CHECKMULTISIG to consume one extra argument
                    # whose contents were not checked in any way.
                    #
                    # Unfortunately this is a potential source of mutability,
                    # so optionally verify it is exactly equal to zero prior
                    # to removing it from the stack.
                    if len(stack) < 1:
                        return ScriptError.INVALID_STACK_OPERATION
                    if flags & SCRIPT_VERIFY_NULLDUMMY and len(stack[-1]):
                        return ScriptError.SIG_NULLDUMMY
                    stack.pop()

                    stack.append(_VCH_TRUE if f_success else _VCH_FALSE)

                    if opcode == opcodes.OP_CHECKMULTISIGVERIFY:
                        if f_success:
                            stack.pop()
                        else:
                            return ScriptError.CHECKMULTISIGVERIFY

                else:
                    return ScriptError.BAD_OPCODE

            # Size limits
            if len(stack) + len(altstack) > MAX_STACK_SIZE:
                return ScriptError.STACK_SIZE
    except ScriptNumError:
        return ScriptError.SCRIPTNUM
    except IndexError:  # Core: catch (...), e.g. std::out_of_range from stack.at()
        return ScriptError.UNKNOWN_ERROR

    if not vf_exec.empty():
        return ScriptError.UNBALANCED_CONDITIONAL

    return _OK


# --- transaction data, sighashes --------------------------------------------------------

class _TxIn:
    __slots__ = ('prevout', 'script_sig', 'sequence', 'witness')

    def __init__(self, prevout: bytes, script_sig: bytes, sequence: int, witness: List[bytes]):
        self.prevout = prevout  # serialized COutPoint (36 bytes)
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = witness


_BLANK_TXOUT = b'\xff' * 8 + b'\x00'  # CTxOut(): nValue = -1, empty scriptPubKey


class PrecomputedTransactionData:
    """Core: PrecomputedTransactionData, plus a snapshot of the transaction fields used by the
    interpreter (so that the Electrum Transaction object is only read once).
    All hashes are computed lazily.
    """

    def __init__(self, tx: 'Transaction', spent_outputs: Optional[Sequence['TxOutput']] = None):
        self.version = tx.version & 0xffffffff  # Core: uint32_t
        self.locktime = tx.locktime
        self.vin = []  # type: List[_TxIn]
        for txin in tx.inputs():
            self.vin.append(_TxIn(txin.prevout.serialize_to_network(), txin.script_sig or b'', txin.nsequence, list(txin.witness_elements())))
        self.vout = [txout.serialize_to_network() for txout in tx.outputs()]
        self.spent_outputs = None  # type: Optional[List[bytes]]
        if spent_outputs is not None:
            if len(spent_outputs) != len(self.vin):
                raise ValueError("need exactly one spent output per input")
            self.spent_outputs = [o.serialize_to_network() for o in spent_outputs]
        self._cache = {}

    def _cached(self, key, fn):
        try:
            return self._cache[key]
        except KeyError:
            v = self._cache[key] = fn()
            return v

    # BIP341 precomputed data (single SHA256)
    @property
    def prevouts_single_hash(self) -> bytes:
        return self._cached('prevouts', lambda: sha256(b''.join(txin.prevout for txin in self.vin)))

    @property
    def sequences_single_hash(self) -> bytes:
        return self._cached('sequences', lambda: sha256(b''.join(struct.pack('<I', txin.sequence) for txin in self.vin)))

    @property
    def outputs_single_hash(self) -> bytes:
        return self._cached('outputs', lambda: sha256(b''.join(self.vout)))

    @property
    def spent_amounts_single_hash(self) -> bytes:
        assert self.spent_outputs is not None
        return self._cached('amounts', lambda: sha256(b''.join(o[:8] for o in self.spent_outputs)))

    @property
    def spent_scripts_single_hash(self) -> bytes:
        assert self.spent_outputs is not None
        return self._cached('scripts', lambda: sha256(b''.join(o[8:] for o in self.spent_outputs)))

    # BIP143 precomputed data (double SHA256)
    @property
    def hash_prevouts(self) -> bytes:
        return self._cached('hash_prevouts', lambda: sha256(self.prevouts_single_hash))

    @property
    def hash_sequence(self) -> bytes:
        return self._cached('hash_sequence', lambda: sha256(self.sequences_single_hash))

    @property
    def hash_outputs(self) -> bytes:
        return self._cached('hash_outputs', lambda: sha256(self.outputs_single_hash))

    def bip341_taproot_ready(self) -> bool:
        return self.spent_outputs is not None

    # Legacy sighash building blocks. Every input with an empty script is 41 bytes, so the
    # serialization of all inputs but one is two slices of these.
    @property
    def legacy_blank_inputs(self) -> bytes:
        return self._cached('blank_in', lambda: b''.join(
            txin.prevout + b'\x00' + struct.pack('<I', txin.sequence) for txin in self.vin))

    @property
    def legacy_blank_inputs_noseq(self) -> bytes:
        return self._cached('blank_in_noseq', lambda: b''.join(
            txin.prevout + b'\x00\x00\x00\x00\x00' for txin in self.vin))

    @property
    def legacy_outputs(self) -> bytes:
        return self._cached('legacy_out', lambda: var_int(len(self.vout)) + b''.join(self.vout))


class SigHashCache:
    """Data structure to cache SHA256 midstates for the ECDSA sighash calculations
    (bare, P2SH, P2WPKH, P2WSH)."""

    def __init__(self):
        # For each sighash mode (ALL, SINGLE, NONE, ALL|ANYONE, SINGLE|ANYONE, NONE|ANYONE),
        # optionally store a scriptCode which the hash is for, plus a midstate for the SHA256
        # computation just before adding the hash_type itself.
        self._entries = [None] * 6

    @staticmethod
    def CacheIndex(hash_type: int) -> int:
        # Note that we do not distinguish between BASE and WITNESS_V0 to determine the cache index,
        # because no input can simultaneously use both.
        return (3 * bool(hash_type & Sighash.ANYONECANPAY)
                + 2 * ((hash_type & 0x1f) == Sighash.SINGLE)
                + 1 * ((hash_type & 0x1f) == Sighash.NONE))

    def Load(self, hash_type: int, script_code: bytes):
        """Returns a copy of the stored SHA256 midstate, or None."""
        entry = self._entries[self.CacheIndex(hash_type)]
        if entry is not None and entry[0] == script_code:
            return entry[1].copy()
        return None

    def Store(self, hash_type: int, script_code: bytes, writer) -> None:
        self._entries[self.CacheIndex(hash_type)] = (script_code, writer.copy())


def SerializeScriptCode(script_code: bytes) -> bytes:
    """Serialize the passed scriptCode, skipping OP_CODESEPARATORs.
    Core: CTransactionSignatureSerializer::SerializeScriptCode. Note that if the script
    does not parse, Core writes the original length but only the bytes up to the point
    where GetOp failed; this is reproduced here.
    """
    end = len(script_code)
    # Core: walk 1, count OP_CODESEPARATORs
    n_code_separators = 0
    it = 0
    while it < end:
        if script_code[it] == opcodes.OP_CODESEPARATOR:
            n_code_separators += 1
        nxt = _next_op(script_code, it, end)
        if nxt < 0:
            break
        it = nxt
    if n_code_separators == 0 and it == end:
        return var_int(end) + script_code
    # Core: walk 2, write the pieces between OP_CODESEPARATORs
    out = [var_int(end - n_code_separators)]
    it = it_begin = 0
    while True:
        ok, opcode, _, it = GetScriptOp(script_code, it)
        if not ok:
            break
        if opcode == opcodes.OP_CODESEPARATOR:
            out.append(script_code[it_begin:it - 1])
            it_begin = it
    if it_begin != end:
        out.append(script_code[it_begin:it])
    return b''.join(out)


def _SignatureHash(script_code: bytes, txdata: PrecomputedTransactionData, n_in: int, hash_type: int,
                   amount: int, sigversion: SigVersion, sighash_cache: SigHashCache = None,
                   budget: VerificationBudget = None) -> bytes:
    """Core: SignatureHash. Returns the 32-byte message, in uint256 byte order."""
    assert n_in < len(txdata.vin)
    hash_type_ser = (hash_type & 0xffffffff).to_bytes(4, 'little')  # Core: int32_t, any value
    any_one_can_pay = bool(hash_type & Sighash.ANYONECANPAY)
    hash_single = (hash_type & 0x1f) == Sighash.SINGLE
    hash_none = (hash_type & 0x1f) == Sighash.NONE

    if sigversion != SigVersion.WITNESS_V0:
        # Check for invalid use of SIGHASH_SINGLE
        if hash_single:
            if n_in >= len(txdata.vout):
                #  nOut out of range
                return b'\x01' + bytes(31)  # uint256::ONE

    # Try to compute using cached SHA256 midstate.
    if sighash_cache is not None:
        ss = sighash_cache.Load(hash_type, script_code)
        if ss is not None:
            # Add sighash type and hash.
            ss.update(hash_type_ser)
            if budget is not None:
                budget.charge_sighash_bytes(4 + 32)
            return sha256(ss.digest())

    ss = hashlib.sha256()
    txin = txdata.vin[n_in]
    if sigversion == SigVersion.WITNESS_V0:
        hash_prevouts = hash_sequence = hash_outputs = bytes(32)
        if not any_one_can_pay:
            hash_prevouts = txdata.hash_prevouts
        if not any_one_can_pay and not hash_single and not hash_none:
            hash_sequence = txdata.hash_sequence
        if not hash_single and not hash_none:
            hash_outputs = txdata.hash_outputs
        elif hash_single and n_in < len(txdata.vout):
            hash_outputs = sha256d(txdata.vout[n_in])
        preimage = b''.join((
            struct.pack('<I', txdata.version),
            # Input prevouts/nSequence (none/all, depending on flags)
            hash_prevouts,
            hash_sequence,
            # The input being signed (replacing the scriptSig with scriptCode + amount)
            txin.prevout,
            var_int(len(script_code)), script_code,
            amount.to_bytes(8, 'little'),
            struct.pack('<I', txin.sequence),
            # Outputs (none/one/all, depending on flags)
            hash_outputs,
            struct.pack('<I', txdata.locktime),
        ))
        n_bytes = len(preimage)
        if budget is not None:
            budget.charge_sighash_bytes(n_bytes + 4 + 32)
        ss.update(preimage)
    else:
        # Core: CTransactionSignatureSerializer
        if budget is not None:
            budget.charge_script_walk(len(script_code))
        script_code_ser = SerializeScriptCode(script_code)
        this_input = txin.prevout + script_code_ser + struct.pack('<I', txin.sequence)
        parts = [struct.pack('<I', txdata.version)]
        if any_one_can_pay:
            # In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
            parts += [b'\x01', this_input]
        else:
            # Blank out other inputs' signatures; with SINGLE or NONE, let the others update at will
            blank = memoryview(txdata.legacy_blank_inputs_noseq if (hash_single or hash_none)
                               else txdata.legacy_blank_inputs)
            parts += [var_int(len(txdata.vin)), blank[:41 * n_in], this_input, blank[41 * (n_in + 1):]]
        if hash_none:
            parts.append(b'\x00')
        elif hash_single:
            # Do not lock-in the txout payee at other indices as txin
            parts += [var_int(n_in + 1), _BLANK_TXOUT * n_in, txdata.vout[n_in]]
        else:
            parts.append(txdata.legacy_outputs)
        parts.append(struct.pack('<I', txdata.locktime))
        if budget is not None:
            budget.charge_sighash_bytes(sum(len(p) for p in parts) + 4 + 32)
        for p in parts:
            ss.update(p)

    # If a cache object was provided, store the midstate there.
    if sighash_cache is not None:
        sighash_cache.Store(hash_type, script_code, ss)

    # Add sighash type and hash.
    ss.update(hash_type_ser)
    return sha256(ss.digest())


def _SignatureHashSchnorr(execdata: ScriptExecutionData, txdata: PrecomputedTransactionData, in_pos: int,
                          hash_type: int, sigversion: SigVersion) -> Optional[bytes]:
    """Core: SignatureHashSchnorr (with MissingDataBehavior::FAIL). Returns None on failure."""
    if sigversion == SigVersion.TAPROOT:
        ext_flag = 0
        key_version = None  # not used
    elif sigversion == SigVersion.TAPSCRIPT:
        ext_flag = 1
        # key_version must be 0 for now, representing the current version of
        # 32-byte public keys in the tapscript signature opcode execution.
        key_version = 0
    else:
        raise AssertionError("unexpected sigversion")
    assert in_pos < len(txdata.vin)
    if not txdata.bip341_taproot_ready():
        return None  # Core: HandleMissingData(MissingDataBehavior::FAIL)

    preimage = []
    # Epoch
    preimage.append(b'\x00')
    # Hash type
    output_type = Sighash.ALL if hash_type == Sighash.DEFAULT else (hash_type & SIGHASH_OUTPUT_MASK)
    input_type = hash_type & SIGHASH_INPUT_MASK
    if not Sighash.is_valid(hash_type, is_taproot=True):
        return None
    preimage.append(bytes((hash_type,)))

    # Transaction level data
    preimage.append(struct.pack('<II', txdata.version, txdata.locktime))
    if input_type != Sighash.ANYONECANPAY:
        preimage.append(txdata.prevouts_single_hash)
        preimage.append(txdata.spent_amounts_single_hash)
        preimage.append(txdata.spent_scripts_single_hash)
        preimage.append(txdata.sequences_single_hash)
    if output_type == Sighash.ALL:
        preimage.append(txdata.outputs_single_hash)

    # Data about the input/prevout being spent
    assert execdata.annex_present is not None
    have_annex = execdata.annex_present
    spend_type = (ext_flag << 1) + (1 if have_annex else 0)  # The low bit indicates whether an annex is present.
    preimage.append(bytes((spend_type,)))
    txin = txdata.vin[in_pos]
    if input_type == Sighash.ANYONECANPAY:
        preimage.append(txin.prevout)
        preimage.append(txdata.spent_outputs[in_pos])
        preimage.append(struct.pack('<I', txin.sequence))
    else:
        preimage.append(struct.pack('<I', in_pos))
    if have_annex:
        preimage.append(execdata.annex_hash)

    # Data about the output (if only one).
    if output_type == Sighash.SINGLE:
        if in_pos >= len(txdata.vout):
            return None
        if execdata.output_hash is None:
            execdata.output_hash = sha256(txdata.vout[in_pos])
        preimage.append(execdata.output_hash)

    # Additional data for BIP 342 signatures
    if sigversion == SigVersion.TAPSCRIPT:
        assert execdata.tapleaf_hash is not None
        preimage.append(execdata.tapleaf_hash)
        preimage.append(bytes((key_version,)))
        assert execdata.codeseparator_pos is not None
        preimage.append(struct.pack('<I', execdata.codeseparator_pos))

    return bip340_tagged_hash(b"TapSighash", b''.join(preimage))


class BaseSignatureChecker:
    budget = None  # type: Optional[VerificationBudget]

    def CheckECDSASignature(self, sig: bytes, pubkey: bytes, script_code: bytes, sigversion: SigVersion) -> bool:
        return False

    def CheckSchnorrSignature(self, sig: bytes, pubkey: bytes, sigversion: SigVersion,
                              execdata: ScriptExecutionData) -> ScriptError:
        # Core: returns false without setting serror, which is UNKNOWN_ERROR inside EvalScript
        return ScriptError.UNKNOWN_ERROR

    def CheckLockTime(self, lock_time: int) -> bool:
        return False

    def CheckSequence(self, sequence: int) -> bool:
        return False


_PUBKEY_LEN_BY_HEADER = {2: 33, 3: 33, 4: 65, 6: 65, 7: 65}  # Core: CPubKey::GetLen


class TransactionSignatureChecker(BaseSignatureChecker):
    """Core: GenericTransactionSignatureChecker with MissingDataBehavior::FAIL."""

    def __init__(self, txdata: PrecomputedTransactionData, txin_index: int, amount: Optional[int], *,
                 budget: VerificationBudget = None):
        if not (0 <= txin_index < len(txdata.vin)):
            raise ValueError(f"txin_index {txin_index} out of range")
        self.txdata = txdata
        self.n_in = txin_index
        self.amount = amount  # None or negative: missing
        self.budget = budget
        self.sighash_cache = SigHashCache()

    def VerifyECDSASignature(self, sig: bytes, pubkey: bytes, sighash: bytes) -> bool:
        """Core: CPubKey::Verify. sig is DER (lax) without the hashtype byte."""
        try:
            key = ecc.ECPubkey(pubkey)
        except ecc.InvalidECPointException:
            return False
        compact = ecdsa_signature_parse_der_lax(sig)
        if compact is None:
            return False
        # libsecp256k1's ECDSA verification requires lower-S signatures, which have
        # not historically been enforced in Bitcoin, so normalize them first.
        return key.ecdsa_verify(compact, sighash, enforce_low_s=False)

    def VerifySchnorrSignature(self, sig: bytes, pubkey: bytes, sighash: bytes) -> bool:
        """Core: XOnlyPubKey::VerifySchnorr"""
        try:
            key = ecc.ECPubkey(b'\x02' + pubkey)
        except ecc.InvalidECPointException:
            return False
        return key.schnorr_verify(bytes(sig), sighash)

    def CheckECDSASignature(self, sig: bytes, pubkey: bytes, script_code: bytes, sigversion: SigVersion) -> bool:
        # Core: CPubKey::IsValid
        if not pubkey or len(pubkey) != _PUBKEY_LEN_BY_HEADER.get(pubkey[0]):
            return False
        # Hash type is one byte tacked on to the end of the signature
        if not sig:
            return False
        hash_type = sig[-1]
        sig = sig[:-1]
        # Witness sighashes need the amount.
        if sigversion == SigVersion.WITNESS_V0 and (self.amount is None or self.amount < 0):
            return False  # Core: HandleMissingData(MissingDataBehavior::FAIL)
        sighash = _SignatureHash(script_code, self.txdata, self.n_in, hash_type, self.amount or 0, sigversion,
                                 self.sighash_cache, self.budget)
        if self.budget is not None:
            self.budget.charge_sig_check()
        return self.VerifyECDSASignature(sig, pubkey, sighash)

    def CheckSchnorrSignature(self, sig: bytes, pubkey: bytes, sigversion: SigVersion,
                              execdata: ScriptExecutionData) -> ScriptError:
        assert sigversion == SigVersion.TAPROOT or sigversion == SigVersion.TAPSCRIPT
        # Schnorr signatures have 32-byte public keys. The caller is responsible for enforcing this.
        assert len(pubkey) == 32
        # Note that in Tapscript evaluation, empty signatures are treated specially (invalid signature that does not
        # abort script execution). This is implemented in EvalChecksigTapscript, which won't invoke
        # CheckSchnorrSignature in that case. In other contexts, they are invalid like every other signature with
        # size different from 64 or 65.
        if len(sig) != 64 and len(sig) != 65:
            return ScriptError.SCHNORR_SIG_SIZE
        hash_type = Sighash.DEFAULT
        if len(sig) == 65:
            hash_type = sig[64]
            sig = sig[:64]
            if hash_type == Sighash.DEFAULT:
                return ScriptError.SCHNORR_SIG_HASHTYPE
        sighash = _SignatureHashSchnorr(execdata, self.txdata, self.n_in, hash_type, sigversion)
        if sighash is None:
            return ScriptError.SCHNORR_SIG_HASHTYPE
        if self.budget is not None:
            self.budget.charge_sig_check()
        if not self.VerifySchnorrSignature(sig, pubkey, sighash):
            return ScriptError.SCHNORR_SIG
        return _OK

    def CheckLockTime(self, lock_time: int) -> bool:
        tx_lock_time = self.txdata.locktime
        # There are two kinds of nLockTime: lock-by-blockheight and lock-by-blocktime,
        # distinguished by whether nLockTime < LOCKTIME_THRESHOLD.
        #
        # We want to compare apples to apples, so fail the script unless the type of
        # nLockTime being tested is the same as the nLockTime in the transaction.
        if not ((tx_lock_time < LOCKTIME_THRESHOLD and lock_time < LOCKTIME_THRESHOLD)
                or (tx_lock_time >= LOCKTIME_THRESHOLD and lock_time >= LOCKTIME_THRESHOLD)):
            return False
        # Now that we know we're comparing apples-to-apples, the comparison is a simple numeric one.
        if lock_time > tx_lock_time:
            return False
        # Finally the nLockTime feature can be disabled in IsFinalTx() and thus CHECKLOCKTIMEVERIFY
        # bypassed if every txin has been finalized by setting nSequence to maxint. Testing if this
        # vin is not final is sufficient to prevent this condition.
        if self.txdata.vin[self.n_in].sequence == SEQUENCE_FINAL:
            return False
        return True

    def CheckSequence(self, sequence: int) -> bool:
        # Relative lock times are supported by comparing the passed in operand to the sequence
        # number of the input.
        tx_to_sequence = self.txdata.vin[self.n_in].sequence
        # Fail if the transaction's version number is not set high enough to trigger BIP 68 rules.
        if self.txdata.version < 2:
            return False
        # Sequence numbers with their most significant bit set are not consensus constrained.
        # Testing that the transaction's sequence number do not have this bit set prevents using
        # this property to get around a CHECKSEQUENCEVERIFY check.
        if tx_to_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return False
        # Mask off any bits that do not have consensus-enforced meaning before doing the integer comparisons
        lock_time_mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
        tx_to_sequence_masked = tx_to_sequence & lock_time_mask
        sequence_masked = sequence & lock_time_mask
        # There are two kinds of nSequence: lock-by-blockheight and lock-by-blocktime,
        # distinguished by whether nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        if not ((tx_to_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG and sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
                or (tx_to_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG and sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG)):
            return False
        # Now that we know we're comparing apples-to-apples, the comparison is a simple numeric one.
        if sequence_masked > tx_to_sequence_masked:
            return False
        return True


def ExecuteWitnessScript(stack_span: Sequence[bytes], exec_script: bytes, flags: int, sigversion: SigVersion,
                         checker: BaseSignatureChecker, execdata: ScriptExecutionData) -> ScriptError:
    stack = list(stack_span)

    if sigversion == SigVersion.TAPSCRIPT:
        # OP_SUCCESSx processing overrides everything, including stack element size limits
        pc = 0
        end = len(exec_script)
        while pc < end:
            opcode = exec_script[pc]
            pc = _next_op(exec_script, pc, end)
            if pc < 0:
                # Note how this condition would not be reached if an unknown OP_SUCCESSx was found
                return ScriptError.BAD_OPCODE
            # New opcodes will be listed here. May use a different sigversion to modify existing opcodes.
            if _IS_OP_SUCCESS[opcode]:
                if flags & SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS:
                    return ScriptError.DISCOURAGE_OP_SUCCESS
                return _OK
        # Tapscript enforces initial stack size limits (altstack is empty here)
        if len(stack) > MAX_STACK_SIZE:
            return ScriptError.STACK_SIZE

    # Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    for elem in stack:
        if len(elem) > MAX_SCRIPT_ELEMENT_SIZE:
            return ScriptError.PUSH_SIZE

    # Run the script interpreter.
    err = EvalScript(stack, exec_script, flags, checker, sigversion, execdata)
    if err is not _OK:
        return err

    # Scripts inside witness implicitly require cleanstack behaviour
    if len(stack) != 1:
        return ScriptError.CLEANSTACK
    if not CastToBool(stack[-1]):
        return ScriptError.EVAL_FALSE
    return _OK


def ComputeTapleafHash(leaf_version: int, script: bytes) -> bytes:
    return bip340_tagged_hash(b"TapLeaf", bytes((leaf_version,)) + witness_push(script))


def ComputeTapbranchHash(a: bytes, b: bytes) -> bytes:
    return bip340_tagged_hash(b"TapBranch", a + b if a < b else b + a)


def ComputeTaprootMerkleRoot(control: bytes, tapleaf_hash: bytes) -> bytes:
    assert len(control) >= TAPROOT_CONTROL_BASE_SIZE
    assert len(control) <= TAPROOT_CONTROL_MAX_SIZE
    assert (len(control) - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0
    path_len = (len(control) - TAPROOT_CONTROL_BASE_SIZE) // TAPROOT_CONTROL_NODE_SIZE
    k = tapleaf_hash
    for i in range(path_len):
        pos = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i
        k = ComputeTapbranchHash(k, bytes(control[pos:pos + TAPROOT_CONTROL_NODE_SIZE]))
    return k


def CheckTapTweak(output_key: bytes, internal_key: bytes, merkle_root: bytes, parity: int) -> bool:
    """Core: XOnlyPubKey::CheckTapTweak (secp256k1_xonly_pubkey_tweak_add_check)"""
    try:
        q_parity, q = taproot_tweak_pubkey(internal_key, merkle_root)
    except (ecc.InvalidECPointException, ValueError):  # internal key not on the curve, or tweak >= order
        return False
    return q == output_key and q_parity == parity


def VerifyTaprootCommitment(control: bytes, program: bytes, tapleaf_hash: bytes,
                            budget: VerificationBudget = None) -> bool:
    assert len(control) >= TAPROOT_CONTROL_BASE_SIZE
    assert len(program) >= 32
    # The internal pubkey (x-only, so no Y coordinate parity).
    p = bytes(control[1:TAPROOT_CONTROL_BASE_SIZE])
    # The output pubkey (taken from the scriptPubKey).
    q = bytes(program)
    # Compute the Merkle root from the leaf and the provided path.
    merkle_root = ComputeTaprootMerkleRoot(control, tapleaf_hash)
    # Verify that the output pubkey matches the tweaked internal pubkey, after correcting for parity.
    if budget is not None:
        budget.charge_sig_check()
    return CheckTapTweak(q, p, merkle_root, control[0] & 1)


def VerifyWitnessProgram(witness: Sequence[bytes], witversion: int, program: bytes, flags: int,
                         checker: BaseSignatureChecker, is_p2sh: bool) -> ScriptError:
    stack = list(witness)
    execdata = ScriptExecutionData()

    if witversion == 0:
        if len(program) == WITNESS_V0_SCRIPTHASH_SIZE:
            # BIP141 P2WSH: 32-byte witness v0 program (which encodes SHA256(script))
            if len(stack) == 0:
                return ScriptError.WITNESS_PROGRAM_WITNESS_EMPTY
            exec_script = stack.pop()
            if sha256(exec_script) != program:
                return ScriptError.WITNESS_PROGRAM_MISMATCH
            return ExecuteWitnessScript(stack, exec_script, flags, SigVersion.WITNESS_V0, checker, execdata)
        elif len(program) == WITNESS_V0_KEYHASH_SIZE:
            # BIP141 P2WPKH: 20-byte witness v0 program (which encodes Hash160(pubkey))
            if len(stack) != 2:
                return ScriptError.WITNESS_PROGRAM_MISMATCH  # 2 items in witness
            exec_script = pubkeyhash_to_p2pkh_script(program)
            return ExecuteWitnessScript(stack, exec_script, flags, SigVersion.WITNESS_V0, checker, execdata)
        else:
            return ScriptError.WITNESS_PROGRAM_WRONG_LENGTH
    elif witversion == 1 and len(program) == WITNESS_V1_TAPROOT_SIZE and not is_p2sh:
        # BIP341 Taproot: 32-byte non-P2SH witness v1 program (which encodes a P2C-tweaked pubkey)
        if not flags & SCRIPT_VERIFY_TAPROOT:
            return _OK
        if len(stack) == 0:
            return ScriptError.WITNESS_PROGRAM_WITNESS_EMPTY
        if len(stack) >= 2 and len(stack[-1]) and stack[-1][0] == ANNEX_TAG:
            # Drop annex (this is non-standard; see IsWitnessStandard)
            annex = stack.pop()
            execdata.annex_hash = sha256(witness_push(annex))
            execdata.annex_present = True
        else:
            execdata.annex_present = False
        if len(stack) == 1:
            # Key path spending (stack size is 1 after removing optional annex)
            return checker.CheckSchnorrSignature(stack[0], program, SigVersion.TAPROOT, execdata)
        else:
            # Script path spending (stack size is >1 after removing optional annex)
            control = stack.pop()
            script = stack.pop()
            if (len(control) < TAPROOT_CONTROL_BASE_SIZE or len(control) > TAPROOT_CONTROL_MAX_SIZE
                    or (len(control) - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0):
                return ScriptError.TAPROOT_WRONG_CONTROL_SIZE
            execdata.tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, script)
            if not VerifyTaprootCommitment(control, program, execdata.tapleaf_hash, checker.budget):
                return ScriptError.WITNESS_PROGRAM_MISMATCH
            if (control[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT:
                # Tapscript (leaf version 0xc0)
                execdata.validation_weight_left = len(construct_witness(witness)) + VALIDATION_WEIGHT_OFFSET
                return ExecuteWitnessScript(stack, script, flags, SigVersion.TAPSCRIPT, checker, execdata)
            if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION:
                return ScriptError.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
            return _OK
    elif not is_p2sh and IsPayToAnchor(witversion, program):
        return _OK
    else:
        if flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            return ScriptError.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
        # Other version/size/p2sh combinations return true for future softfork compatibility
        return _OK


def verify_script(script_sig: bytes, script_pubkey: bytes, witness: Optional[Sequence[bytes]], flags: int,
                  checker: BaseSignatureChecker) -> ScriptError:
    """Core: VerifyScript. Returns ScriptError.OK on success.
    Raises ValueError for flag combinations that Core asserts against (see is_valid_flag_combination).
    """
    flags = int(flags)
    if not is_valid_flag_combination(flags):
        raise ValueError(f"invalid script verification flag combination: {flags:#x}")
    if witness is None:
        witness = ()
    had_witness = False

    if flags & SCRIPT_VERIFY_SIGPUSHONLY and not IsPushOnly(script_sig):
        return ScriptError.SIG_PUSHONLY

    # scriptSig and scriptPubKey must be evaluated sequentially on the same stack
    # rather than being simply concatenated (see CVE-2010-5141)
    stack = []  # type: List[bytes]
    err = EvalScript(stack, script_sig, flags, checker, SigVersion.BASE)
    if err is not _OK:
        return err
    stack_copy = list(stack) if flags & SCRIPT_VERIFY_P2SH else None
    err = EvalScript(stack, script_pubkey, flags, checker, SigVersion.BASE)
    if err is not _OK:
        return err
    if not stack:
        return ScriptError.EVAL_FALSE
    if not CastToBool(stack[-1]):
        return ScriptError.EVAL_FALSE

    # Bare witness programs
    if flags & SCRIPT_VERIFY_WITNESS:
        wp = IsWitnessProgram(script_pubkey)
        if wp is not None:
            had_witness = True
            if len(script_sig) != 0:
                # The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                return ScriptError.WITNESS_MALLEATED
            err = VerifyWitnessProgram(witness, wp[0], wp[1], flags, checker, is_p2sh=False)
            if err is not _OK:
                return err
            # Bypass the cleanstack check at the end. The actual stack is obviously not clean
            # for witness programs.
            del stack[1:]

    # Additional validation for spend-to-script-hash transactions:
    if flags & SCRIPT_VERIFY_P2SH and IsPayToScriptHash(script_pubkey):
        # scriptSig must be literals-only or validation fails
        if not IsPushOnly(script_sig):
            return ScriptError.SIG_PUSHONLY

        # Restore stack.
        stack, stack_copy = stack_copy, stack

        # stack cannot be empty here, because if it was the
        # P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        # an empty stack and the EvalScript above would return false.
        assert stack

        pub_key_2 = stack.pop()

        err = EvalScript(stack, pub_key_2, flags, checker, SigVersion.BASE)
        if err is not _OK:
            return err
        if not stack:
            return ScriptError.EVAL_FALSE
        if not CastToBool(stack[-1]):
            return ScriptError.EVAL_FALSE

        # P2SH witness program
        if flags & SCRIPT_VERIFY_WITNESS:
            wp = IsWitnessProgram(pub_key_2)
            if wp is not None:
                had_witness = True
                if script_sig != _push_data(pub_key_2):
                    # The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
                    # reintroduce malleability.
                    return ScriptError.WITNESS_MALLEATED_P2SH
                err = VerifyWitnessProgram(witness, wp[0], wp[1], flags, checker, is_p2sh=True)
                if err is not _OK:
                    return err
                # Bypass the cleanstack check at the end. The actual stack is obviously not clean
                # for witness programs.
                del stack[1:]

    # The CLEANSTACK check is only performed after potential P2SH evaluation,
    # as the non-P2SH evaluation of a P2SH script will obviously not result in
    # a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
    if flags & SCRIPT_VERIFY_CLEANSTACK:
        # Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        # would be possible, which is not a softfork (and P2SH should be one).
        assert flags & SCRIPT_VERIFY_P2SH
        assert flags & SCRIPT_VERIFY_WITNESS
        if len(stack) != 1:
            return ScriptError.CLEANSTACK

    if flags & SCRIPT_VERIFY_WITNESS:
        # We can't check for correct unexpected witness data if P2SH was off, so require
        # that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        # possible, which is not a softfork.
        assert flags & SCRIPT_VERIFY_P2SH
        if not had_witness and len(witness) != 0:
            return ScriptError.WITNESS_UNEXPECTED

    return _OK


def WitnessSigOps(witversion: int, witprogram: bytes, witness: Sequence[bytes]) -> int:
    if witversion == 0:
        if len(witprogram) == WITNESS_V0_KEYHASH_SIZE:
            return 1

        if len(witprogram) == WITNESS_V0_SCRIPTHASH_SIZE and len(witness) > 0:
            return GetSigOpCount(witness[-1], True)

    # Future flags may be implemented here.
    return 0


def CountWitnessSigOps(script_sig: bytes, script_pubkey: bytes, witness: Sequence[bytes], flags: int) -> int:
    if not flags & SCRIPT_VERIFY_WITNESS:
        return 0
    if not flags & SCRIPT_VERIFY_P2SH:  # Core: assert
        raise ValueError(f"invalid script verification flag combination: {flags:#x}")

    wp = IsWitnessProgram(script_pubkey)
    if wp is not None:
        return WitnessSigOps(wp[0], wp[1], witness)

    if IsPayToScriptHash(script_pubkey) and IsPushOnly(script_sig):
        pc = 0
        data = b''
        while pc < len(script_sig):
            _, _, data, pc = GetScriptOp(script_sig, pc)
        wp = IsWitnessProgram(data)
        if wp is not None:
            return WitnessSigOps(wp[0], wp[1], witness)

    return 0


# --- public API -------------------------------------------------------------------------
# Electrum deserializes a Transaction lazily: if its serialization is malformed, the first field
# access raises transaction.SerializationError (as tx.txid() would). Core deserializes before
# validating, so callers should pass a tx that has been deserialized already.

def signature_hash_legacy(script_code: bytes, tx: 'Transaction', txin_index: int, hash_type: int) -> bytes:
    """Legacy (pre-segwit) signature hash, in the byte order that is signed.
    hash_type may be any 32-bit value (it is serialized as is).
    """
    txdata = PrecomputedTransactionData(tx)
    return _SignatureHash(script_code, txdata, txin_index, hash_type, 0, SigVersion.BASE)


def signature_hash_witness_v0(script_code: bytes, tx: 'Transaction', txin_index: int, hash_type: int,
                              amount: int, txdata: PrecomputedTransactionData = None) -> bytes:
    """BIP143 signature hash."""
    if txdata is None:
        txdata = PrecomputedTransactionData(tx)
    return _SignatureHash(script_code, txdata, txin_index, hash_type, amount, SigVersion.WITNESS_V0)


def signature_hash_schnorr(tx: 'Transaction', txin_index: int, hash_type: int, sigversion: SigVersion,
                           txdata: PrecomputedTransactionData = None, *, annex: bytes = None,
                           tapleaf_hash: bytes = None, codesep_pos: int = 0xffffffff) -> Optional[bytes]:
    """BIP341/BIP342 signature hash. Returns None where Core's SignatureHashSchnorr fails
    (invalid hash_type, SIGHASH_SINGLE without matching output, missing spent outputs)."""
    if txdata is None:
        txdata = PrecomputedTransactionData(tx)
    execdata = ScriptExecutionData()
    execdata.annex_present = annex is not None
    if annex is not None:
        execdata.annex_hash = sha256(witness_push(annex))
    execdata.tapleaf_hash = tapleaf_hash
    execdata.codeseparator_pos = codesep_pos
    return _SignatureHashSchnorr(execdata, txdata, txin_index, hash_type, sigversion)


def verify_input(tx: 'Transaction', txin_index: int, spent_outputs: Sequence['TxOutput'], *,
                 flags: int = CONSENSUS_FLAGS, txdata: PrecomputedTransactionData = None,
                 budget: VerificationBudget = None) -> None:
    """Checks that input txin_index of tx validly spends spent_outputs[txin_index].
    spent_outputs must contain the outputs spent by all inputs of tx (taproot signatures
    commit to all of them).
    Raises ScriptVerificationError, or ResourceLimitExceeded if the budget is exhausted.
    Raises ValueError on API misuse (index out of range, len(spent_outputs) != number of inputs,
    flag combinations that Core asserts against).
    """
    if txdata is None:
        txdata = PrecomputedTransactionData(tx, spent_outputs)
    if len(spent_outputs) != len(txdata.vin):
        raise ValueError("need exactly one spent output per input")
    if not (0 <= txin_index < len(txdata.vin)):
        raise ValueError(f"txin_index {txin_index} out of range")
    spent = spent_outputs[txin_index]
    txin = txdata.vin[txin_index]
    checker = TransactionSignatureChecker(txdata, txin_index, spent.value, budget=budget)
    err = verify_script(txin.script_sig, spent.scriptpubkey, txin.witness, flags, checker)
    if err is not _OK:
        raise ScriptVerificationError(err, txin_index)


def _is_null_prevout(prevout: bytes) -> bool:
    return prevout == bytes(32) + b'\xff\xff\xff\xff'


def _is_coinbase(inputs) -> bool:
    return len(inputs) == 1 and _is_null_prevout(inputs[0].prevout.serialize_to_network())


def _stripped_size(inputs, outputs) -> int:
    """Core: GetSerializeSize(TX_NO_WITNESS(tx))"""
    size = 4 + len(var_int(len(inputs))) + len(var_int(len(outputs))) + 4
    for txin in inputs:
        script_sig = txin.script_sig or b''
        size += 36 + len(var_int(len(script_sig))) + len(script_sig) + 4
    for txout in outputs:
        size += 8 + len(var_int(len(txout.scriptpubkey))) + len(txout.scriptpubkey)
    return size


def GetTransactionWeight(tx: 'Transaction') -> int:
    """Core: GetTransactionWeight (consensus/validation.h)"""
    inputs = tx.inputs()
    stripped_size = _stripped_size(inputs, tx.outputs())
    witnesses = [txin.witness_elements() for txin in inputs]
    total_size = stripped_size
    if any(witnesses):  # Core: CTransaction::HasWitness
        total_size += 2  # marker and flag
        for witness in witnesses:
            total_size += len(var_int(len(witness)))
            total_size += sum(len(var_int(len(item))) + len(item) for item in witness)
    return stripped_size * (WITNESS_SCALE_FACTOR - 1) + total_size


def GetLegacySigOpCount(tx: 'Transaction') -> int:
    """Core: GetLegacySigOpCount (consensus/tx_verify.cpp)"""
    n_sigops = 0
    for txin in tx.inputs():
        n_sigops += GetSigOpCount(txin.script_sig or b'', False)
    for txout in tx.outputs():
        n_sigops += GetSigOpCount(txout.scriptpubkey, False)
    return n_sigops


def GetP2SHSigOpCount(tx: 'Transaction', spent_outputs: Sequence['TxOutput']) -> int:
    """Core: GetP2SHSigOpCount (consensus/tx_verify.cpp)"""
    if _is_coinbase(tx.inputs()):
        return 0

    n_sigops = 0
    for txin, prevout in zip(tx.inputs(), spent_outputs, strict=True):
        if IsPayToScriptHash(prevout.scriptpubkey):
            n_sigops += GetSigOpCountWithScriptSig(prevout.scriptpubkey, txin.script_sig or b'')
    return n_sigops


def GetTransactionSigOpCost(tx: 'Transaction', spent_outputs: Sequence['TxOutput'], flags: int) -> int:
    """Core: GetTransactionSigOpCost (consensus/tx_verify.cpp). spent_outputs as in
    verify_transaction (unused for a coinbase). Raises ValueError on API misuse, as verify_input.
    """
    n_sigops = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR

    if _is_coinbase(tx.inputs()):
        return n_sigops
    if len(spent_outputs) != len(tx.inputs()):
        raise ValueError("need exactly one spent output per input")

    if flags & SCRIPT_VERIFY_P2SH:
        n_sigops += GetP2SHSigOpCount(tx, spent_outputs) * WITNESS_SCALE_FACTOR

    for txin, prevout in zip(tx.inputs(), spent_outputs):
        n_sigops += CountWitnessSigOps(txin.script_sig or b'', prevout.scriptpubkey, txin.witness_elements(), flags)
    return n_sigops


def check_transaction(tx: 'Transaction') -> None:
    """Core: CheckTransaction. Basic checks that don't depend on any context.
    Raises TxValidationError with Core's reject reason."""
    inputs = tx.inputs()
    outputs = tx.outputs()
    if not inputs:
        raise TxValidationError("bad-txns-vin-empty")
    if not outputs:
        raise TxValidationError("bad-txns-vout-empty")
    # Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if _stripped_size(inputs, outputs) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
        raise TxValidationError("bad-txns-oversize")

    # Check for negative or overflow output values (see CVE-2010-5139)
    value_out = 0
    for txout in outputs:
        if txout.value < 0:
            raise TxValidationError("bad-txns-vout-negative")
        if txout.value > MAX_MONEY:
            raise TxValidationError("bad-txns-vout-toolarge")
        value_out += txout.value
        if not MoneyRange(value_out):
            raise TxValidationError("bad-txns-txouttotal-toolarge")

    # Check for duplicate inputs (see CVE-2018-17144)
    prevouts = [txin.prevout.serialize_to_network() for txin in inputs]
    if len(set(prevouts)) != len(prevouts):
        raise TxValidationError("bad-txns-inputs-duplicate")

    if len(inputs) == 1 and _is_null_prevout(prevouts[0]):  # coinbase
        if not (2 <= len(inputs[0].script_sig or b'') <= 100):
            raise TxValidationError("bad-cb-length")
    else:
        for prevout in prevouts:
            if _is_null_prevout(prevout):
                raise TxValidationError("bad-txns-prevout-null")


def verify_transaction(tx: 'Transaction', spent_outputs: Sequence['TxOutput'], *,
                       flags: int = CONSENSUS_FLAGS, budget: VerificationBudget = None) -> None:
    """Checks that tx is a valid non-coinbase transaction spending spent_outputs (one per input,
    in order), as far as this is possible without the UTXO set: context-free checks, the block
    weight and sigop cost limits, input and output value rules, and the scripts/signatures of all
    inputs. Locktimes and sequence locks are not checked against the chain.
    Raises TxValidationError, ScriptVerificationError, or ResourceLimitExceeded (the budget was
    exhausted; the tx may well be valid). ValueError on API misuse, as verify_input.
    """
    check_transaction(tx)
    inputs = tx.inputs()
    if _is_coinbase(inputs):
        raise TxValidationError("coinbase")  # cannot be in the mempool
    if len(spent_outputs) != len(inputs):
        raise ValueError("need exactly one spent output per input")
    # A tx that exceeds a block limit on its own cannot be in any block.
    # Core: ContextualCheckBlock
    if GetTransactionWeight(tx) > MAX_BLOCK_WEIGHT:
        raise TxValidationError("bad-blk-weight")
    # Core: Consensus::CheckTxInputs
    value_in = 0
    for spent in spent_outputs:
        # Check for negative or overflow input values
        value_in += spent.value
        if not MoneyRange(spent.value) or not MoneyRange(value_in):
            raise TxValidationError("bad-txns-inputvalues-outofrange")
    value_out = sum(txout.value for txout in tx.outputs())
    if value_in < value_out:
        raise TxValidationError("bad-txns-in-belowout")
    # Core: ConnectBlock
    if GetTransactionSigOpCost(tx, spent_outputs, flags) > MAX_BLOCK_SIGOPS_COST:
        raise TxValidationError("bad-blk-sigops")

    txdata = PrecomputedTransactionData(tx, spent_outputs)
    for i in range(len(inputs)):
        verify_input(tx, i, spent_outputs, flags=flags, txdata=txdata, budget=budget)
