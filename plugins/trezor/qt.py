from plugins.trezor.qt_generic import QtPlugin
from trezorlib.qt.pinmatrix import PinMatrixWidget

class Plugin(QtPlugin):
    pin_matrix_widget_class = PinMatrixWidget
    icon_file = ":icons/trezor.png"
