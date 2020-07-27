from .util import read_QIcon
from .main_window import ElectrumWindow
from electrum.i18n import _
from .recovery_list import RecoveryTab


class ElectrumARWindow(ElectrumWindow):
    def __init__(self, gui_object: 'ElectrumGui', wallet: 'Abstract_Wallet'):
        super().__init__(gui_object=gui_object, wallet=wallet)
        self.recovery_tab = self.create_recovery_tab(wallet, self.config)
        # todo add proper icon
        self.tabs.addTab(self.recovery_tab, read_QIcon('recovery.png'), _('Recovery'))

    def create_recovery_tab(self, wallet: 'Abstract_Wallet', config):
        return RecoveryTab(self, wallet, config)

    def sweep_key_dialog(self):
        self.wallet.set_alert()
        super().sweep_key_dialog()

    def pay_multiple_invoices(self, invoices):
        self.wallet.set_alert()
        super().pay_multiple_invoices(invoices)

    def do_pay_invoice(self, invoice):
        self.wallet.set_alert()
        super().do_pay_invoice(invoice)

    def show_recovery_tab(self):
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.recovery_tab))
