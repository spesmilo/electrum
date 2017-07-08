from ..trezor.qt_generic import QtPlugin
from trezor import TrezorPlugin


class Plugin(TrezorPlugin, QtPlugin):
    icon_unpaired = ":icons/trezor_unpaired.png"
    icon_paired = ":icons/trezor.png"

    @classmethod
    def pin_matrix_widget_class(self):
        from trezorlib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget
