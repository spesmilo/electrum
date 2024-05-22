# Copyright (c) 2018 Andrew R. Kozlik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

"""
This implements the high-level functions for SLIP-39, also called "Shamir Backup".

See https://github.com/satoshilabs/slips/blob/master/slip-0039.md.
"""

import hmac
from collections import defaultdict
from hashlib import pbkdf2_hmac
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .i18n import _
from .mnemonic import Wordlist

Indices = Tuple[int, ...]
MnemonicGroups = Dict[int, Tuple[int, Set[Tuple[int, bytes]]]]


"""
## Simple helpers
"""

_RADIX_BITS = 10
"""The length of the radix in bits."""


def _bits_to_bytes(n: int) -> int:
    return (n + 7) // 8


def _bits_to_words(n: int) -> int:
    return (n + _RADIX_BITS - 1) // _RADIX_BITS


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


"""
## Constants
"""

_ID_LENGTH_BITS = 15
"""The length of the random identifier in bits."""

_ITERATION_EXP_LENGTH_BITS = 4
"""The length of the iteration exponent in bits."""

_EXTENDABLE_BACKUP_FLAG_LENGTH_BITS = 1
"""The length of the extendable backup flag in bits."""

_ID_EXP_LENGTH_WORDS = _bits_to_words(
    _ID_LENGTH_BITS + _EXTENDABLE_BACKUP_FLAG_LENGTH_BITS + _ITERATION_EXP_LENGTH_BITS
)
"""The length of the random identifier, extendable backup flag and iteration exponent in words."""

_INDEX_LENGTH_BITS = 4
"""The length of the group index, group threshold, group count, and member index in bits."""

_CHECKSUM_LENGTH_WORDS = 3
"""The length of the RS1024 checksum in words."""

_DIGEST_LENGTH_BYTES = 4
"""The length of the digest of the shared secret in bytes."""

_CUSTOMIZATION_STRING_NON_EXTENDABLE = b"shamir"
"""The customization string used in the RS1024 checksum and in the PBKDF2 salt when extendable backup flag is not set."""

_CUSTOMIZATION_STRING_EXTENDABLE = b"shamir_extendable"
"""The customization string used in the RS1024 checksum when extendable backup flag is set."""

_GROUP_PREFIX_LENGTH_WORDS = _ID_EXP_LENGTH_WORDS + 1
"""The length of the prefix of the mnemonic that is common to a share group."""

_METADATA_LENGTH_WORDS = _ID_EXP_LENGTH_WORDS + 2 + _CHECKSUM_LENGTH_WORDS
"""The length of the mnemonic in words without the share value."""

_MIN_STRENGTH_BITS = 128
"""The minimum allowed entropy of the master secret."""

_MIN_MNEMONIC_LENGTH_WORDS = _METADATA_LENGTH_WORDS + _bits_to_words(_MIN_STRENGTH_BITS)
"""The minimum allowed length of the mnemonic in words."""

_BASE_ITERATION_COUNT = 10000
"""The minimum number of iterations to use in PBKDF2."""

_ROUND_COUNT = 4
"""The number of rounds to use in the Feistel cipher."""

_SECRET_INDEX = 255
"""The index of the share containing the shared secret."""

_DIGEST_INDEX = 254
"""The index of the share containing the digest of the shared secret."""


"""
# External API
"""


class Slip39Error(RuntimeError):
    pass


class Share:
    """
    Represents a single mnemonic and offers its parsed metadata.
    """

    def __init__(
        self,
        identifier: int,
        extendable_backup_flag: bool,
        iteration_exponent: int,
        group_index: int,
        group_threshold: int,
        group_count: int,
        member_index: int,
        member_threshold: int,
        share_value: bytes,
    ):
        self.index = None
        self.identifier = identifier
        self.extendable_backup_flag = extendable_backup_flag
        self.iteration_exponent = iteration_exponent
        self.group_index = group_index
        self.group_threshold = group_threshold
        self.group_count = group_count
        self.member_index = member_index
        self.member_threshold = member_threshold
        self.share_value = share_value

    def common_parameters(self) -> tuple:
        """Return the values that uniquely identify a matching set of shares."""
        return (
            self.identifier,
            self.extendable_backup_flag,
            self.iteration_exponent,
            self.group_threshold,
            self.group_count,
        )


class EncryptedSeed:
    """
    Represents the encrypted master seed for BIP-32.
    """

    def __init__(
        self,
        identifier: int,
        extendable_backup_flag: bool,
        iteration_exponent: int,
        encrypted_master_secret: bytes,
    ):
        self.identifier = identifier
        self.extendable_backup_flag = extendable_backup_flag
        self.iteration_exponent = iteration_exponent
        self.encrypted_master_secret = encrypted_master_secret

    def decrypt(self, passphrase: str) -> bytes:
        """
        Converts the Encrypted Master Secret to a Master Secret by applying the passphrase.
        This is analogous to BIP-39 passphrase derivation. We do not use the term "derive"
        here, because passphrase function is symmetric in SLIP-39. We are using the terms
        "encrypt" and "decrypt" instead.
        """
        passphrase = (passphrase or '').encode('utf-8')
        ems_len = len(self.encrypted_master_secret)
        l = self.encrypted_master_secret[: ems_len // 2]
        r = self.encrypted_master_secret[ems_len // 2 :]
        salt = _get_salt(self.identifier, self.extendable_backup_flag)
        for i in reversed(range(_ROUND_COUNT)):
            (l, r) = (
                r,
                _xor(l, _round_function(i, passphrase, self.iteration_exponent, salt, r)),
            )
        return r + l


def recover_ems(mnemonics: List[str]) -> EncryptedSeed:
    """
    Combines mnemonic shares to obtain the encrypted master secret which was previously
    split using Shamir's secret sharing scheme.
    Returns identifier, iteration exponent and the encrypted master secret.
    """

    if not mnemonics:
        raise Slip39Error("The list of mnemonics is empty.")

    (
        identifier,
        extendable_backup_flag,
        iteration_exponent,
        group_threshold,
        group_count,
        groups,
    ) = _decode_mnemonics(mnemonics)

    # Use only groups that have at least the threshold number of shares.
    groups = {group_index: group for group_index, group in groups.items() if len(group[1]) >= group[0]}

    if len(groups) < group_threshold:
        raise Slip39Error(
            "Insufficient number of mnemonic groups. Expected {} full groups, but {} were provided.".format(
                group_threshold, len(groups)
            )
        )

    group_shares = [
        (group_index, _recover_secret(group[0], list(group[1])))
        for group_index, group in groups.items()
    ]

    encrypted_master_secret = _recover_secret(group_threshold, group_shares)
    return EncryptedSeed(
        identifier, extendable_backup_flag, iteration_exponent, encrypted_master_secret
    )


def decode_mnemonic(mnemonic: str) -> Share:
    """Converts a share mnemonic to share data."""

    mnemonic_data = tuple(_mnemonic_to_indices(mnemonic))

    if len(mnemonic_data) < _MIN_MNEMONIC_LENGTH_WORDS:
        raise Slip39Error(_('Too short.'))

    padding_len = (_RADIX_BITS * (len(mnemonic_data) - _METADATA_LENGTH_WORDS)) % 16
    if padding_len > 8:
        raise Slip39Error(_('Invalid length.'))

    idExpExtInt = _int_from_indices(mnemonic_data[:_ID_EXP_LENGTH_WORDS])
    identifier = idExpExtInt >> (
        _EXTENDABLE_BACKUP_FLAG_LENGTH_BITS + _ITERATION_EXP_LENGTH_BITS
    )
    extendable_backup_flag = bool(
        (idExpExtInt >> _ITERATION_EXP_LENGTH_BITS)
        & ((1 << _EXTENDABLE_BACKUP_FLAG_LENGTH_BITS) - 1)
    )
    iteration_exponent = idExpExtInt & ((1 << _ITERATION_EXP_LENGTH_BITS) - 1)

    if not _rs1024_verify_checksum(mnemonic_data, extendable_backup_flag):
        raise Slip39Error(_('Invalid mnemonic checksum.'))

    tmp = _int_from_indices(
        mnemonic_data[_ID_EXP_LENGTH_WORDS : _ID_EXP_LENGTH_WORDS + 2]
    )
    (
        group_index,
        group_threshold,
        group_count,
        member_index,
        member_threshold,
    ) = _int_to_indices(tmp, 5, _INDEX_LENGTH_BITS)
    value_data = mnemonic_data[_ID_EXP_LENGTH_WORDS + 2 : -_CHECKSUM_LENGTH_WORDS]

    if group_count < group_threshold:
        raise Slip39Error(_('Invalid mnemonic group threshold.'))

    value_byte_count = _bits_to_bytes(_RADIX_BITS * len(value_data) - padding_len)
    value_int = _int_from_indices(value_data)
    if value_data[0] >= 1 << (_RADIX_BITS - padding_len):
        raise Slip39Error(_('Invalid mnemonic padding.'))
    value = value_int.to_bytes(value_byte_count, "big")

    return Share(
        identifier,
        extendable_backup_flag,
        iteration_exponent,
        group_index,
        group_threshold + 1,
        group_count + 1,
        member_index,
        member_threshold + 1,
        value,
    )


def get_wordlist() -> Wordlist:
    wordlist = Wordlist.from_file('slip39.txt')

    required_words = 2**_RADIX_BITS
    if len(wordlist) != required_words:
        raise Slip39Error(
            f"The wordlist should contain {required_words} words, but it contains {len(wordlist)} words."
        )

    return wordlist


def process_mnemonics(mnemonics: List[str]) -> Tuple[Optional[EncryptedSeed], str]:
    # Collect valid shares.
    shares = []
    for i, mnemonic in enumerate(mnemonics):
        try:
            share = decode_mnemonic(mnemonic)
            share.index = i + 1
            shares.append(share)
        except Slip39Error:
            pass

    if not shares:
        return None, _('No valid shares.')

    # Sort shares into groups.
    groups: Dict[int, Set[Share]] = defaultdict(set)  # group idx : shares
    common_params = shares[0].common_parameters()
    for share in shares:
        if share.common_parameters() != common_params:
            error_text = _("Share #{} is not part of the current set.").format(share.index)
            return None, _ERROR_STYLE % error_text
        for other in groups[share.group_index]:
            if share.member_index == other.member_index:
                error_text = _("Share #{} is a duplicate of share #{}.").format(share.index, other.index)
                return None, _ERROR_STYLE % error_text
        groups[share.group_index].add(share)

    # Compile information about groups.
    groups_completed = 0
    for i, group in groups.items():
        if group:
            member_threshold = next(iter(group)).member_threshold
            if len(group) >= member_threshold:
                groups_completed += 1

    identifier = shares[0].identifier
    extendable_backup_flag = shares[0].extendable_backup_flag
    iteration_exponent = shares[0].iteration_exponent
    group_threshold = shares[0].group_threshold
    group_count = shares[0].group_count
    status = ''
    if group_count > 1:
        status += _('Completed {} of {} groups needed').format(f"<b>{groups_completed}</b>", f"<b>{group_threshold}</b>")
        status += ":<br/>"

    for group_index in range(group_count):
        group_prefix = _make_group_prefix(
            identifier,
            extendable_backup_flag,
            iteration_exponent,
            group_index,
            group_threshold,
            group_count,
        )
        status += _group_status(groups[group_index], group_prefix)

    if groups_completed >= group_threshold:
        if len(mnemonics) > len(shares):
            status += _ERROR_STYLE % _('Some shares are invalid.')
        else:
            try:
                encrypted_seed = recover_ems(mnemonics)
                status += '<b>' + _('The set is complete!') + '</b>'
            except Slip39Error as e:
                encrypted_seed = None
                status = _ERROR_STYLE % str(e)
            return encrypted_seed, status

    return None, status


"""
## Group status helpers
"""

_FINISHED = '<span style="color:green;">&#x2714;</span>'
_EMPTY = '<span style="color:red;">&#x2715;</span>'
_INPROGRESS = '<span style="color:orange;">&#x26ab;</span>'
_ERROR_STYLE = '<span style="color:red; font-weight:bold;">' + _('Error') + ': %s</span>'

def _make_group_prefix(
    identifier,
    extendable_backup_flag,
    iteration_exponent,
    group_index,
    group_threshold,
    group_count,
):
    wordlist = get_wordlist()
    val = identifier
    val <<= _EXTENDABLE_BACKUP_FLAG_LENGTH_BITS
    val += int(extendable_backup_flag)
    val <<= _ITERATION_EXP_LENGTH_BITS
    val += iteration_exponent
    val <<= _INDEX_LENGTH_BITS
    val += group_index
    val <<= _INDEX_LENGTH_BITS
    val += group_threshold - 1
    val <<= _INDEX_LENGTH_BITS
    val += group_count - 1
    val >>= 2
    prefix = ' '.join(wordlist[idx] for idx in _int_to_indices(val, _GROUP_PREFIX_LENGTH_WORDS, _RADIX_BITS))
    return prefix


def _group_status(group: Set[Share], group_prefix) -> str:
    len(group)
    if not group:
        return _EMPTY + _('{} shares from group {}').format('<b>0</b> ', f'<b>{group_prefix}</b>') + f'.<br/>'
    else:
        share = next(iter(group))
        icon = _FINISHED if len(group) >= share.member_threshold else _INPROGRESS
        return icon + _('{} of {} shares needed from group {}').format(f'<b>{len(group)}</b>', f'<b>{share.member_threshold}</b>', f'<b>{group_prefix}</b>') + f'.<br/>'


"""
## Convert mnemonics or integers to indices and back
"""


def _int_from_indices(indices: Indices) -> int:
    """Converts a list of base 1024 indices in big endian order to an integer value."""
    value = 0
    for index in indices:
        value = (value << _RADIX_BITS) + index
    return value


def _int_to_indices(value: int, output_length: int, bits: int) -> Iterable[int]:
    """Converts an integer value to indices in big endian order."""
    mask = (1 << bits) - 1
    return ((value >> (i * bits)) & mask for i in reversed(range(output_length)))


def _mnemonic_to_indices(mnemonic: str) -> List[int]:
    wordlist = get_wordlist()
    indices = []
    for word in mnemonic.split():
        try:
            indices.append(wordlist.index(word.lower()))
        except ValueError:
            if len(word) > 8:
                word = word[:8] + '...'
            raise Slip39Error(_('Invalid mnemonic word') + ' "%s".' % word) from None
    return indices


"""
## Checksum functions
"""


def _get_customization_string(extendable_backup_flag: bool) -> bytes:
    if extendable_backup_flag:
        return _CUSTOMIZATION_STRING_EXTENDABLE
    else:
        return _CUSTOMIZATION_STRING_NON_EXTENDABLE


def _rs1024_polymod(values: Indices) -> int:
    GEN = (
        0xE0E040,
        0x1C1C080,
        0x3838100,
        0x7070200,
        0xE0E0009,
        0x1C0C2412,
        0x38086C24,
        0x3090FC48,
        0x21B1F890,
        0x3F3F120,
    )
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _rs1024_verify_checksum(data: Indices, extendable_backup_flag: bool) -> bool:
    """
    Verifies a checksum of the given mnemonic, which was already parsed into Indices.
    """
    return (
        _rs1024_polymod(tuple(_get_customization_string(extendable_backup_flag)) + data)
        == 1
    )


"""
## Internal functions
"""


def _precompute_exp_log() -> Tuple[List[int], List[int]]:
    exp = [0 for i in range(255)]
    log = [0 for i in range(256)]

    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i

        # Multiply poly by the polynomial x + 1.
        poly = (poly << 1) ^ poly

        # Reduce poly by x^8 + x^4 + x^3 + x + 1.
        if poly & 0x100:
            poly ^= 0x11B

    return exp, log


_EXP_TABLE, _LOG_TABLE = _precompute_exp_log()


def _interpolate(shares, x) -> bytes:
    """
    Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
    :param shares: The Shamir shares.
    :type shares: A list of pairs (x_i, y_i), where x_i is an integer and y_i is an array of
        bytes representing the evaluations of the polynomials in x_i.
    :param int x: The x coordinate of the result.
    :return: Evaluations of the polynomials in x.
    :rtype: Array of bytes.
    """

    x_coordinates = set(share[0] for share in shares)

    if len(x_coordinates) != len(shares):
        raise Slip39Error("Invalid set of shares. Share indices must be unique.")

    share_value_lengths = set(len(share[1]) for share in shares)
    if len(share_value_lengths) != 1:
        raise Slip39Error(
            "Invalid set of shares. All share values must have the same length."
        )

    if x in x_coordinates:
        for share in shares:
            if share[0] == x:
                return share[1]

    # Logarithm of the product of (x_i - x) for i = 1, ... , k.
    log_prod = sum(_LOG_TABLE[share[0] ^ x] for share in shares)

    result = bytes(share_value_lengths.pop())
    for share in shares:
        # The logarithm of the Lagrange basis polynomial evaluated at x.
        log_basis_eval = (
            log_prod
            - _LOG_TABLE[share[0] ^ x]
            - sum(_LOG_TABLE[share[0] ^ other[0]] for other in shares)
        ) % 255

        result = bytes(
            intermediate_sum
            ^ (
                _EXP_TABLE[(_LOG_TABLE[share_val] + log_basis_eval) % 255]
                if share_val != 0
                else 0
            )
            for share_val, intermediate_sum in zip(share[1], result)
        )

    return result


def _round_function(i: int, passphrase: bytes, e: int, salt: bytes, r: bytes) -> bytes:
    """The round function used internally by the Feistel cipher."""
    return pbkdf2_hmac(
        "sha256",
        bytes([i]) + passphrase,
        salt + r,
        (_BASE_ITERATION_COUNT << e) // _ROUND_COUNT,
        dklen=len(r),
    )


def _get_salt(identifier: int, extendable_backup_flag: bool) -> bytes:
    if extendable_backup_flag:
        return bytes()
    else:
        return _CUSTOMIZATION_STRING_NON_EXTENDABLE + identifier.to_bytes(
            _bits_to_bytes(_ID_LENGTH_BITS), "big"
        )


def _create_digest(random_data: bytes, shared_secret: bytes) -> bytes:
    return hmac.new(random_data, shared_secret, "sha256").digest()[:_DIGEST_LENGTH_BYTES]


def _recover_secret(threshold: int, shares: List[Tuple[int, bytes]]) -> bytes:
    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return shares[0][1]

    shared_secret = _interpolate(shares, _SECRET_INDEX)
    digest_share = _interpolate(shares, _DIGEST_INDEX)
    digest = digest_share[:_DIGEST_LENGTH_BYTES]
    random_part = digest_share[_DIGEST_LENGTH_BYTES:]

    if digest != _create_digest(random_part, shared_secret):
        raise Slip39Error("Invalid digest of the shared secret.")

    return shared_secret


def _decode_mnemonics(
    mnemonics: List[str],
) -> Tuple[int, int, int, int, MnemonicGroups]:
    identifiers = set()
    extendable_backup_flags = set()
    iteration_exponents = set()
    group_thresholds = set()
    group_counts = set()

    # { group_index : [threshold, set_of_member_shares] }
    groups = {}  # type: MnemonicGroups
    for mnemonic in mnemonics:
        share = decode_mnemonic(mnemonic)
        identifiers.add(share.identifier)
        extendable_backup_flags.add(share.extendable_backup_flag)
        iteration_exponents.add(share.iteration_exponent)
        group_thresholds.add(share.group_threshold)
        group_counts.add(share.group_count)
        group = groups.setdefault(share.group_index, (share.member_threshold, set()))
        if group[0] != share.member_threshold:
            raise Slip39Error(
                "Invalid set of mnemonics. All mnemonics in a group must have the same member threshold."
            )
        group[1].add((share.member_index, share.share_value))

    if (
        len(identifiers) != 1
        or len(extendable_backup_flags) != 1
        or len(iteration_exponents) != 1
    ):
        raise Slip39Error(
            "Invalid set of mnemonics. All mnemonics must begin with the same {} words.".format(
                _ID_EXP_LENGTH_WORDS
            )
        )

    if len(group_thresholds) != 1:
        raise Slip39Error(
            "Invalid set of mnemonics. All mnemonics must have the same group threshold."
        )

    if len(group_counts) != 1:
        raise Slip39Error(
            "Invalid set of mnemonics. All mnemonics must have the same group count."
        )

    for group_index, group in groups.items():
        if len(set(share[0] for share in group[1])) != len(group[1]):
            raise Slip39Error(
                "Invalid set of shares. Member indices in each group must be unique."
            )

    return (
        identifiers.pop(),
        extendable_backup_flags.pop(),
        iteration_exponents.pop(),
        group_thresholds.pop(),
        group_counts.pop(),
        groups,
    )
