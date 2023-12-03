# Copyright (C) 2023 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import sys


# FIXME: remove when both desktop and mobile are Qt6
def get_qt_major_version() -> int:
    _GUI_QT_VERSION = getattr(sys, '_GUI_QT_VERSION', None)
    if _GUI_QT_VERSION is None:
        # used by pyinstaller when building (analysis phase)
        _GUI_QT_VERSION = 5
    if _GUI_QT_VERSION in (5, 6):
        return _GUI_QT_VERSION
    raise Exception(f"unexpected {_GUI_QT_VERSION=}")
