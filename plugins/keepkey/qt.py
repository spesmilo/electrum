from plugins.trezor.qt_generic import QtPlugin


class Plugin(QtPlugin):
    icon_file = ":icons/keepkey.png"

    def pin_matrix_widget_class():
        from keepkeylib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget
