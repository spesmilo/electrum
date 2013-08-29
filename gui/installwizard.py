from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
from i18n import _

from electrum import Wallet, mnemonic, WalletVerifier, WalletSynchronizer

from seed_dialog import SeedDialog
from network_dialog import NetworkDialog
from qt_util import *
from amountedit import AmountEdit

import sys

class InstallWizard(QDialog):

    def __init__(self, config, interface):
        QDialog.__init__(self)
        self.config = config
        self.interface = interface


    def restore_or_create(self):
        msg = _("Wallet file not found.")+"\n"+_("Do you want to create a new wallet, or to restore an existing one?")
        r = QMessageBox.question(None, _('Message'), msg, _('Create'), _('Restore'), _('Cancel'), 0, 2)
        if r==2: return None
        return 'restore' if r==1 else 'create'


    def verify_seed(self, wallet):
        r = self.seed_dialog(False)
        if r != wallet.seed:
            QMessageBox.warning(None, _('Error'), 'incorrect seed', 'OK')
            return False
        else:
            return True


    def seed_dialog(self, is_restore=True):
        d = QDialog()
        d.setModal(1)

        vbox = QVBoxLayout()
        if is_restore:
            msg = _("Please enter your wallet seed (or your master public key if you want to create a watching-only wallet)." + ' ')
        else:
            msg = _("Your seed is important! To make sure that you have properly saved your seed, please type it here." + ' ')

        msg += _("Your seed can be entered as a sequence of words, or as a hexadecimal string."+ '\n')
        
        label=QLabel(msg)
        label.setWordWrap(True)
        vbox.addWidget(label)

        seed_e = QTextEdit()
        seed_e.setMaximumHeight(100)
        vbox.addWidget(seed_e)

        if is_restore:
            grid = QGridLayout()
            grid.setSpacing(8)
            gap_e = AmountEdit(None, True)
            gap_e.setText("5")
            grid.addWidget(QLabel(_('Gap limit')), 2, 0)
            grid.addWidget(gap_e, 2, 1)
            grid.addWidget(HelpButton(_('Keep the default value unless you modified this parameter in your wallet.')), 2, 3)
            vbox.addLayout(grid)

        vbox.addLayout(ok_cancel_buttons(d))
        d.setLayout(vbox) 

        if not d.exec_(): return

        try:
            seed = str(seed_e.toPlainText())
            seed.decode('hex')
        except:
            try:
                seed = mnemonic.mn_decode( seed.split() )
            except:
                QMessageBox.warning(None, _('Error'), _('I cannot decode this'), _('OK'))
                return

        if not seed:
            QMessageBox.warning(None, _('Error'), _('No seed'), _('OK'))
            return

        if not is_restore:
            return seed
        else:
            try:
                gap = int(unicode(gap_e.text()))
            except:
                QMessageBox.warning(None, _('Error'), 'error', 'OK')
                return
            return seed, gap


    def network_dialog(self):
        return NetworkDialog(self.interface, self.config, None).do_exec()
        

    def show_seed(self, wallet):
        d = SeedDialog()
        d.show_seed(wallet.seed, wallet.imported_keys)


    def password_dialog(self, wallet):
        from password_dialog import PasswordDialog
        d = PasswordDialog(wallet)
        d.run()


    def restore_wallet(self, wallet):

        # wait until we are connected, because the user might have selected another server
        if not wallet.interface.is_connected:
            waiting = lambda: False if wallet.interface.is_connected else "%s \n" % (_("Connecting..."))
            waiting_dialog(waiting)

        waiting = lambda: False if wallet.is_up_to_date() else "%s\n%s %d\n%s %.1f"\
            %(_("Please wait..."),_("Addresses generated:"),len(wallet.addresses(True)),_("Kilobytes received:"), wallet.interface.bytes_received/1024.)

        wallet.set_up_to_date(False)
        wallet.interface.poke('synchronizer')
        waiting_dialog(waiting)
        if wallet.is_found():
            QMessageBox.information(None, _('Information'), _("Recovery successful"), _('OK'))
        else:
            QMessageBox.information(None, _('Information'), _("No transactions found for this seed"), _('OK'))

        return True


    def run(self):

        a = self.restore_or_create()
        if not a: exit()

        wallet = Wallet(self.config)
        wallet.interface = self.interface

        if a =='create':
            wallet.init_seed(None)
            self.show_seed(wallet)
            if self.verify_seed(wallet):
                wallet.save_seed()
            else:
                exit()
        else:
            # ask for seed and gap.
            sg = self.seed_dialog()
            if not sg: exit()
            seed, gap = sg
            if not seed: exit()
            wallet.gap_limit = gap
            if len(seed) == 128:
                wallet.seed = ''
                wallet.init_sequence(str(seed))
            else:
                wallet.init_seed(str(seed))
                wallet.save_seed()

        # select a server.
        s = self.network_dialog()
        if s is None:
            self.config.set_key("server", None, True)
            self.config.set_key('auto_cycle', False, True)

        self.interface.start(wait = False)

        # start wallet threads
        verifier = WalletVerifier(self.interface, self.config)
        verifier.start()
        wallet.set_verifier(verifier)
        synchronizer = WalletSynchronizer(wallet, self.config)
        synchronizer.start()


        # generate the first addresses, in case we are offline
        if s is None or a == 'create':
            wallet.synchronize()


        if a == 'restore' and s is not None:
            try:
                keep_it = self.restore_wallet(wallet)
                wallet.fill_addressbook()
            except:
                import traceback
                traceback.print_exc(file=sys.stdout)
                exit()

            if not keep_it: exit()


        self.password_dialog(wallet)
