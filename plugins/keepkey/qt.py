from ..trezor.qt_generic import qt_plugin_class
from keepkey import KeepKeyPlugin


class Plugin(qt_plugin_class(KeepKeyPlugin)):
    icon_file = ":icons/keepkey.png"

    @classmethod
    def pin_matrix_widget_class(self):
        from keepkeylib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget
