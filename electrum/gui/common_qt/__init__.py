# Copyright (C) 2023 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Mapping, Optional


def version_info() -> Mapping[str, Optional[str]]:
    try:
        import PyQt6
        from PyQt6.QtCore import QT_VERSION_STR, PYQT_VERSION_STR
    except ImportError:
        return {"qt.version": None, "pyqt.version": None}
    ret = {
        "qt.version": QT_VERSION_STR,
        "pyqt.version": PYQT_VERSION_STR,
    }
    if hasattr(PyQt6, "__path__"):
        ret["pyqt.path"] = ", ".join(PyQt6.__path__ or [])
    return ret
