from plugins.trezor.qt_generic import QtPlugin
from keepkeylib.qt.pinmatrix import PinMatrixWidget

class Plugin(QtPlugin):
    handler_class = KeepKeyQtHandler
    icon_file = ":icons/keepkey.png"
