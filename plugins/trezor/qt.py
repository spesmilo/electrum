from plugins.trezor.qt_generic import QtPlugin


class Plugin(QtPlugin):
    icon_file = ":icons/trezor.png"

    @staticmethod
    def pin_matrix_widget_class():
        from trezorlib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget
