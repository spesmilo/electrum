from ..trezor.qt_generic import qt_plugin_class
from trezor import TrezorPlugin


class Plugin(qt_plugin_class(TrezorPlugin)):
    icon_file = ":icons/trezor.png"

    @classmethod
    def pin_matrix_widget_class(self):
        from trezorlib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget
