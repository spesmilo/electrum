from ..trezor.qt_generic import QtPlugin
from keepkey import KeepKeyPlugin


class Plugin(KeepKeyPlugin, QtPlugin):
    icon_paired = ":icons/keepkey.png"
    icon_unpaired = ":icons/keepkey_unpaired.png"

    @classmethod
    def pin_matrix_widget_class(self):
        from keepkeylib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget
