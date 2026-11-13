# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

"""Uniform Resources (BC-UR 2.0), e.g. for (animated) QR codes containing PSBTs.

https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md
https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2024-001-multipart-ur.md
"""

import re
from typing import Optional, Sequence, Tuple

from . import cbor
from .i18n import _
from .logging import Logger
from ._vendor.bc_ur.bytewords import Bytewords, Bytewords_Style_minimal
from ._vendor.bc_ur.fountain_decoder import FountainDecoder
from ._vendor.bc_ur.fountain_encoder import Part
from ._vendor.bc_ur.ur import UR
from ._vendor.bc_ur.ur_decoder import URDecoder
from ._vendor.bc_ur.ur_encoder import UREncoder as _UREncoder


# 'crypto-psbt' is deprecated in favour of 'psbt' (BCR-2020-006), but many
# signing devices (e.g. Jade, Keystone, SeedSigner) only accept 'crypto-psbt'.
UR_TYPE_CRYPTO_PSBT = 'crypto-psbt'
# UR types accepted for transactions. 'bytes' is not meant for this,
# but some wallets use it for PSBTs and raw transactions.
TX_UR_TYPES = (UR_TYPE_CRYPTO_PSBT, 'psbt', 'bytes')
# URs should not be tagged, but be lenient
_PSBT_CBOR_TAGS = (310, 40310)

# note: re.ASCII, as with re.IGNORECASE alone, [a-z] would also match some non-ASCII letters
_MULTIPART_UR_RE = re.compile(r'ur:[a-z0-9-]+/[0-9]+-[0-9]+/[a-z]+', re.IGNORECASE | re.ASCII)


class URError(ValueError):
    pass


def is_ur(text: str) -> bool:
    return text[:3].lower() == 'ur:'


def is_multipart_ur(text: str) -> bool:
    """Whether text is one part of a multi-part UR, i.e. of an animated QR code."""
    return _MULTIPART_UR_RE.fullmatch(text) is not None


class UREncoder:
    """Encodes payload as (multi-part) UR, to be shown as (animated) QR code."""

    MIN_FRAGMENT_LEN = 10

    def __init__(self, ur_type: str, payload: bytes, *, max_fragment_len: int):
        self.ur_type = ur_type
        self.payload = bytes(payload)
        message = cbor.dumps(self.payload)
        max_fragment_len = max(max_fragment_len, self.MIN_FRAGMENT_LEN)
        # the fountain encoder requires the message to be at least min_fragment_len long
        min_fragment_len = min(self.MIN_FRAGMENT_LEN, len(message))
        self._encoder = _UREncoder(UR(ur_type, message), max_fragment_len, min_fragment_len=min_fragment_len)

    @property
    def is_single_part(self) -> bool:
        return self._encoder.is_single_part()

    def next_part(self) -> str:
        """Returns the next part. After one part per fragment, it continues forever
        with parts that combine several fragments (fountain codes).
        """
        return self._encoder.next_part().upper()


class URScanCollector(Logger):
    """Collects the parts of an animated QR code (multi-part UR), scanned one by one.
    add() returns the assembled UR once complete, and other scanned text as is.
    """

    # After this many consecutive QR codes that do not belong to the UR in progress (other text,
    # or parts of a different UR), assume that the user is scanning something else, and start over.
    MAX_FOREIGN_PARTS = 10

    def __init__(self):
        Logger.__init__(self)
        self.reset()

    def reset(self) -> None:
        self._ur_type = None  # type: Optional[str]
        self._decoder = None  # type: Optional[FountainDecoder]
        self._num_foreign_parts = 0

    @property
    def in_progress(self) -> bool:
        return self._decoder is not None

    @property
    def progress(self) -> Optional[Tuple[int, int]]:
        """Returns (number of independent parts received, number of fragments) while in progress.
        The UR is complete once they are equal.
        """
        if self._decoder is None:
            return None
        return self._decoder.independent_part_count(), self._decoder.expected_part_count()

    def add(self, text: str) -> Optional[str]:
        """Returns the text to use, or None if more parts are needed."""
        if not is_multipart_ur(text):
            # while scanning an animated QR code, the camera might pick up other QR codes
            if self.in_progress and not self._start_over_after_foreign_qr():
                return None
            return text
        try:
            ur_type, part = self._parse_part(text)
        except URError:
            return None
        if self._decoder is not None and not self._is_same_message(ur_type, part):
            if not self._start_over_after_foreign_qr():
                return None
        self._num_foreign_parts = 0
        if self._decoder is None:
            self.logger.debug(f'started collecting multi-part UR: type={ur_type}, '
                              f'{part.seq_len} fragments, {part.message_len} bytes')
            self._ur_type = ur_type
            self._decoder = FountainDecoder()
        try:
            self._decoder.receive_part(part)
        except Exception:
            return None
        if self._decoder.is_success():
            ur = UR(self._ur_type, self._decoder.result_message())
            self.reset()
            return _UREncoder.encode(ur)
        if self._decoder.is_failure():
            self.logger.warning(f'assembled multi-part UR has a wrong checksum, starting over: '
                                f'type={self._ur_type}, {self._decoder.expected_part_count()} fragments')
            self.reset()
        return None

    def add_frame(self, texts: Sequence[str]) -> Optional[str]:
        """Like add(), for the texts of all QR codes found in one camera frame.
        Returns the first text to use, or None.
        """
        # Feed the parts of an animated QR code first, so that another QR code in the same
        # frame cannot be accepted by an idle collector before the animated scan has started.
        for text in sorted(texts, key=lambda t: not is_multipart_ur(t)):
            if (data := self.add(text)) is not None:
                return data
        return None

    def _start_over_after_foreign_qr(self) -> bool:
        """Counts a QR code that does not belong to the UR in progress.
        Returns whether the limit was reached, and the collector was reset.
        """
        self._num_foreign_parts += 1
        if self._num_foreign_parts < self.MAX_FOREIGN_PARTS:
            return False
        self.reset()
        return True

    @staticmethod
    def _parse_part(text: str) -> Tuple[str, Part]:
        try:
            ur_type, (seq, fragment) = URDecoder.parse(text)
            seq_num, seq_len = URDecoder.parse_sequence_component(seq)
            part = Part.from_cbor(Bytewords.decode(Bytewords_Style_minimal, fragment))
        except Exception as e:
            raise URError('invalid UR part') from e
        if (seq_num, seq_len) != (part.seq_num, part.seq_len):
            raise URError('invalid UR part')
        return ur_type, part

    def _is_same_message(self, ur_type: str, part: Part) -> bool:
        d = self._decoder
        return ur_type == self._ur_type \
                and part.seq_len == d.expected_part_count() \
                and part.message_len == d.expected_message_len \
                and part.checksum == d.expected_checksum \
                and len(part.data) == d.expected_fragment_len


def decode_tx_ur(text: str) -> bytes:
    """Returns the PSBT or raw transaction contained in the UR text.
    The UR must be single-part, or a part that alone contains the whole message.
    """
    if is_multipart_ur(text):
        # a part might contain the whole message (e.g. 'ur:bytes/1-1/...')
        text = URScanCollector().add(text)
        if text is None:
            raise URError(_('This is only one part of an animated QR code. Scan it with the camera to read all its parts.'))
    try:
        ur_type, components = URDecoder.parse(text)
    except Exception as e:
        raise URError(_('Invalid UR')) from e
    if ur_type not in TX_UR_TYPES:
        raise URError(_('Unsupported UR type: {}').format(ur_type))
    if len(components) != 1:  # e.g. UR 1.0
        raise URError(_('Unsupported UR format'))
    try:
        payload = cbor.loads(Bytewords.decode(Bytewords_Style_minimal, components[0]))
    except Exception as e:
        raise URError(_('Invalid UR')) from e
    if isinstance(payload, cbor.CBORTag) and payload.tag in _PSBT_CBOR_TAGS:
        payload = payload.value
    if type(payload) is not bytes:
        raise URError(_('Unexpected UR content'))
    return payload
