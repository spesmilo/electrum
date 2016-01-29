from ..ledger.qt_generic import qt_plugin_class
from ledger import LedgerPlugin

class Plugin(qt_plugin_class(LedgerPlugin)):
    icon_file = ":icons/trezor.png"

#    @classmethod
#    def pin_matrix_widget_class(self):
#        from trezorlib.qt.pinmatrix import PinMatrixWidget
#        return PinMatrixWidget
