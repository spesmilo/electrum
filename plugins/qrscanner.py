from electrum.util import print_error
from urlparse import urlparse, parse_qs
from PyQt4.QtGui import QPushButton, QMessageBox, QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel
from PyQt4.QtCore import Qt
from electrum_gui.i18n import _

import re
from electrum.bitcoin import MIN_RELAY_TX_FEE, Transaction, is_valid
from electrum_gui.qrcodewidget import QRCodeWidget
import electrum_gui.bmp
import json

try:
    import zbar
except ImportError:
    zbar = None

from electrum_gui import BasePlugin
class Plugin(BasePlugin):

    def __init__(self, gui):
        BasePlugin.__init__(self, gui, 'qrscans', 'QR scans', "QR Scans.\nInstall the zbar package (http://zbar.sourceforge.net/download.html) to enable this plugin")
        self._is_available = self._init()
        
    def _init(self):
        if not zbar:
            return False
        try:
            proc = zbar.Processor()
            proc.init()
        except zbar.SystemError:
            # Cannot open video device
            return False

        return True

    def is_available(self):
        return self._is_available

    def create_send_tab(self, grid):
        b = QPushButton(_("Scan QR code"))
        b.clicked.connect(self.fill_from_qr)
        grid.addWidget(b, 1, 5)
        b2 = QPushButton(_("Scan TxQR"))
        b2.clicked.connect(self.read_raw_qr)
        
        if not self.gui.wallet.seed:
            b3 = QPushButton(_("Show unsigned TxQR"))
            b3.clicked.connect(self.show_raw_qr)
            grid.addWidget(b3, 7, 1)
            grid.addWidget(b2, 7, 2)
        else:
            grid.addWidget(b2, 7, 1)


    def scan_qr(self):
        proc = zbar.Processor()
        proc.init()
        proc.visible = True

        while True:
            try:
                proc.process_one()
            except:
                # User closed the preview window
                return {}

            for r in proc.results:
                if str(r.type) != 'QRCODE':
                    continue
                return r.data
        
    def show_raw_qr(self):
        r = unicode( self.gui.payto_e.text() )
        r = r.strip()

        # label or alias, with address in brackets
        m = re.match('(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>', r)
        to_address = m.group(2) if m else r

        if not is_valid(to_address):
            QMessageBox.warning(self.gui, _('Error'), _('Invalid Bitcoin Address') + ':\n' + to_address, _('OK'))
            return

        try:
            amount = self.gui.read_amount(unicode( self.gui.amount_e.text()))
        except:
            QMessageBox.warning(self.gui, _('Error'), _('Invalid Amount'), _('OK'))
            return
        try:
            fee = self.gui.read_amount(unicode( self.gui.fee_e.text()))
        except:
            QMessageBox.warning(self.gui, _('Error'), _('Invalid Fee'), _('OK'))
            return

        try:
            tx = self.gui.wallet.mktx( [(to_address, amount)], None, fee, account=self.gui.current_account)
        except BaseException, e:
            self.gui.show_message(str(e))
            return

        if tx.requires_fee(self.gui.wallet.verifier) and fee < MIN_RELAY_TX_FEE:
            QMessageBox.warning(self.gui, _('Error'), _("This transaction requires a higher fee, or it will not be propagated by the network."), _('OK'))
            return

        try:
            out = {
            "hex" : tx.hash(),
            "complete" : "false"
            }
    
            input_info = []

        except BaseException, e:
            self.gui.show_message(str(e))

        try:
            json_text = json.dumps(tx.as_dict()).replace(' ', '')
            self.show_tx_qrcode(json_text, 'Unsigned Transaction')
        except BaseException, e:
            self.gui.show_message(str(e))

    def show_tx_qrcode(self, data, title):
        if not data: return
        d = QDialog(self.gui)
        d.setModal(1)
        d.setWindowTitle(title)
        d.setMinimumSize(250, 525)
        vbox = QVBoxLayout()
        qrw = QRCodeWidget(data)
        vbox.addWidget(qrw, 0)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        def print_qr(self):
            filename = "qrcode.bmp"
            electrum_gui.bmp.save_qrcode(qrw.qr, filename)
            QMessageBox.information(None, _('Message'), _("QR code saved to file") + " " + filename, _('OK'))

        b = QPushButton(_("Save"))
        hbox.addWidget(b)
        b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(d.accept)
        b.setDefault(True)

        vbox.addLayout(hbox, 1)
        d.setLayout(vbox)
        d.exec_()

    def read_raw_qr(self):
    qrcode = self.scan_qr()
    if qrcode:
        tx_dict = self.gui.tx_dict_from_text(qrcode)
        if tx_dict:
            self.create_transaction_details_window(tx_dict)


    def create_transaction_details_window(self, tx_dict):
        tx = Transaction(tx_dict["hex"])
            
        dialog = QDialog(self.gui)
        dialog.setMinimumWidth(500)
        dialog.setWindowTitle(_('Process Offline transaction'))
        dialog.setModal(1)

        l = QGridLayout()
        dialog.setLayout(l)

        l.addWidget(QLabel(_("Transaction status:")), 3,0)
        l.addWidget(QLabel(_("Actions")), 4,0)

        if tx_dict["complete"] == False:
            l.addWidget(QLabel(_("Unsigned")), 3,1)
            if self.gui.wallet.seed :
                b = QPushButton("Sign transaction")
                input_info = json.loads(tx_dict["input_info"])
                b.clicked.connect(lambda: self.sign_raw_transaction(tx, input_info, dialog))
                l.addWidget(b, 4, 1)
            else:
                l.addWidget(QLabel(_("Wallet is de-seeded, can't sign.")), 4,1)
        else:
            l.addWidget(QLabel(_("Signed")), 3,1)
        b = QPushButton("Broadcast transaction")
            b.clicked.connect(lambda: self.gui.send_raw_transaction(tx, dialog))
            l.addWidget(b,4,1)
    
        l.addWidget( self.gui.generate_transaction_information_widget(tx), 0,0,2,3)
        closeButton = QPushButton(_("Close"))
        closeButton.clicked.connect(lambda: dialog.done(0))
        l.addWidget(closeButton, 4,2)

        dialog.exec_()

    def do_protect(self, func, args):
        if self.gui.wallet.use_encryption:
            password = self.gui.password_dialog()
            if not password:
                return
        else:
            password = None
            
        if args != (False,):
            args = (self,) + args + (password,)
        else:
            args = (self,password)
        apply( func, args)

    def protected(func):
        return lambda s, *args: s.do_protect(func, args)

    @protected
    def sign_raw_transaction(self, tx, input_info, dialog ="", password = ""):
        try:
            self.gui.wallet.signrawtransaction(tx, input_info, [], password)
        txtext = json.dumps(tx.as_dict()).replace(' ', '')
        self.show_tx_qrcode(txtext, 'Signed Transaction')
            
        except BaseException, e:
            self.gui.show_message(str(e))


    def fill_from_qr(self):
        qrcode = parse_uri(self.scan_qr())
        if not qrcode:
            return

        if 'address' in qrcode:
            self.gui.payto_e.setText(qrcode['address'])
        if 'amount' in qrcode:
            self.gui.amount_e.setText(str(qrcode['amount']))
        if 'label' in qrcode:
            self.gui.message_e.setText(qrcode['label'])
        if 'message' in qrcode:
            self.gui.message_e.setText("%s (%s)" % (self.gui.message_e.text(), qrcode['message']))
                



def parse_uri(uri):
    if ':' not in uri:
        # It's just an address (not BIP21)
        return {'address': uri}

    if '//' not in uri:
        # Workaround for urlparse, it don't handle bitcoin: URI properly
        uri = uri.replace(':', '://')
        
    uri = urlparse(uri)
    result = {'address': uri.netloc} 
    
    if uri.path.startswith('?'):
        params = parse_qs(uri.path[1:])
    else:
        params = parse_qs(uri.path)    

    for k,v in params.items():
        if k in ('amount', 'label', 'message'):
            result[k] = v[0]
        
    return result    





if __name__ == '__main__':
    # Run some tests
    
    assert(parse_uri('1Marek48fwU7mugmSe186do2QpUkBnpzSN') ==
           {'address': '1Marek48fwU7mugmSe186do2QpUkBnpzSN'})

    assert(parse_uri('bitcoin://1Marek48fwU7mugmSe186do2QpUkBnpzSN') ==
           {'address': '1Marek48fwU7mugmSe186do2QpUkBnpzSN'})
    
    assert(parse_uri('bitcoin:1Marek48fwU7mugmSe186do2QpUkBnpzSN') ==
           {'address': '1Marek48fwU7mugmSe186do2QpUkBnpzSN'})
    
    assert(parse_uri('bitcoin:1Marek48fwU7mugmSe186do2QpUkBnpzSN?amount=10') ==
           {'amount': '10', 'address': '1Marek48fwU7mugmSe186do2QpUkBnpzSN'})
    
    assert(parse_uri('bitcoin:1Marek48fwU7mugmSe186do2QpUkBnpzSN?amount=10&label=slush&message=Small%20tip%20to%20slush') ==
           {'amount': '10', 'label': 'slush', 'message': 'Small tip to slush', 'address': '1Marek48fwU7mugmSe186do2QpUkBnpzSN'})
    
    
