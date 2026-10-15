#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# A module, that, given an image (buffer), finds and decodes a QR code in it.

from typing import Mapping, Optional

from ..i18n import _
from ..logging import get_logger

from .abstract_base import AbstractQrCodeReader, QrCodeResult


_logger = get_logger(__name__)


class MissingQrDetectionLib(RuntimeError):
    ''' Raised if the library required to detect QR codes is unavailable. '''


def get_qr_reader() -> AbstractQrCodeReader:
    """
    Get the QR code reader.
    Might raise exception: MissingQrDetectionLib.
    """
    try:
        from .zxing import ZXingQrCodeReader
        return ZXingQrCodeReader()
        """
        # DEBUG CODE BELOW
        # If you want to test this code on a platform that doesn't yet work or have
        # zxing-cpp, use the below...
        class Fake(AbstractQrCodeReader):
            def read_qr_code(self, buffer, buffer_size, dummy, width, height, frame_id = -1):
                ''' fake noop to test '''
                return []
        return Fake()
        """
    except MissingLib as e:
        _logger.exception("")
        raise MissingQrDetectionLib(_("The QR detection library is not available.") + f"\n{e}") from e


def version_info() -> Mapping[str, Optional[str]]:
    from .zxing import LIBZXING, LIBZXING_VERSION
    return {
        "libZXing.path": LIBZXING._name if LIBZXING else None,
        "libZXing.version": LIBZXING_VERSION,
    }


# --- Internals below (not part of external API)

class MissingLib(RuntimeError):
    ''' Raised by underlying implementation if missing libs '''
    pass
