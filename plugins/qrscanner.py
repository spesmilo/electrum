from electrum.util import print_error
from urlparse import urlparse, parse_qs
from PyQt4.QtGui import QPushButton, QMessageBox, QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QComboBox
from PyQt4.QtCore import Qt

from electrum.i18n import _
import re
import os
from electrum import Transaction
from electrum.bitcoin import MIN_RELAY_TX_FEE, is_valid
from electrum_gui.qt.qrcodewidget import QRCodeWidget
from electrum import bmp
from electrum_gui.qt import HelpButton, EnterButton
import json

try:
    import zbar
except ImportError:
    zbar = None

from electrum import BasePlugin
class Plugin(BasePlugin):

    def fullname(self): return 'QR scans'

    def description(self): return "QR Scans.\nInstall the zbar package (http://zbar.sourceforge.net/download.html) to enable this plugin"

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        if not zbar:
            return False
        try:
            proc = zbar.Processor()
            proc.init(video_device=self.video_device())
        except zbar.SystemError:
            # Cannot open video device
            pass
            #return False

        return True

    def load_wallet(self, wallet):
        b = QPushButton(_("Scan QR code"))
        b.clicked.connect(self.fill_from_qr)
        self.send_tab_grid.addWidget(b, 1, 5)
        b2 = QPushButton(_("Scan TxQR"))
        b2.clicked.connect(self.read_raw_qr)
        
        if not wallet.seed:
            b3 = QPushButton(_("Show unsigned TxQR"))
            b3.clicked.connect(self.show_raw_qr)
            self.send_tab_grid.addWidget(b3, 7, 1)
            self.send_tab_grid.addWidget(b2, 7, 2)
        else:
            self.send_tab_grid.addWidget(b2, 7, 1)

    def is_available(self):
        return self._is_available

    def create_send_tab(self, grid):
        self.send_tab_grid = grid

    def scan_qr(self):
        proc = zbar.Processor()
        try:
            proc.init(video_device=self.video_device())
        except zbar.SystemError, e:
            QMessageBox.warning(self.gui.main_window, _('Error'), _(e), _('OK'))
            return

        proc.visible = True

        while True:
            try:
                proc.process_one()
            except Exception:
                # User closed the preview window
                return {}

            for r in proc.results:
                if str(r.type) != 'QRCODE':
                    continue
                return r.data
        
    def show_raw_qr(self):
        r = unicode( self.gui.main_window.payto_e.text() )
        r = r.strip()

        # label or alias, with address in brackets
        m = re.match('(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>', r)
        to_address = m.group(2) if m else r

        if not is_valid(to_address):
            QMessageBox.warning(self.gui.main_window, _('Error'), _('Invalid Bitcoin Address') + ':\n' + to_address, _('OK'))
            return

        try:
            amount = self.gui.main_window.read_amount(unicode( self.gui.main_window.amount_e.text()))
        except Exception:
            QMessageBox.warning(self.gui.main_window, _('Error'), _('Invalid Amount'), _('OK'))
            return
        try:
            fee = self.gui.main_window.read_amount(unicode( self.gui.main_window.fee_e.text()))
        except Exception:
            QMessageBox.warning(self.gui.main_window, _('Error'), _('Invalid Fee'), _('OK'))
            return

        try:
            tx = self.gui.main_window.wallet.mktx( [(to_address, amount)], None, fee)
        except Exception as e:
            self.gui.main_window.show_message(str(e))
            return

        if tx.requires_fee(self.gui.main_window.wallet.verifier) and fee < MIN_RELAY_TX_FEE:
            QMessageBox.warning(self.gui.main_window, _('Error'), _("This transaction requires a higher fee, or it will not be propagated by the network."), _('OK'))
            return

        try:
            out = {
            "hex" : tx.hash(),
            "complete" : "false"
            }
    
            input_info = []

        except Exception as e:
            self.gui.main_window.show_message(str(e))

        try:
            json_text = json.dumps(tx.as_dict()).replace(' ', '')
            self.show_tx_qrcode(json_text, 'Unsigned Transaction')
        except Exception as e:
            self.gui.main_window.show_message(str(e))

    def show_tx_qrcode(self, data, title):
        if not data: return
        d = QDialog(self.gui.main_window)
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
            tx = self.gui.main_window.tx_from_text(qrcode)
            if tx:
                self.create_transaction_details_window(tx)

    def create_transaction_details_window(self, tx):            
        dialog = QDialog(self.gui.main_window)
        dialog.setMinimumWidth(500)
        dialog.setWindowTitle(_('Process Offline transaction'))
        dialog.setModal(1)

        l = QGridLayout()
        dialog.setLayout(l)

        l.addWidget(QLabel(_("Transaction status:")), 3,0)
        l.addWidget(QLabel(_("Actions")), 4,0)

        if tx.is_complete == False:
            l.addWidget(QLabel(_("Unsigned")), 3,1)
            if self.gui.main_window.wallet.seed :
                b = QPushButton("Sign transaction")
                b.clicked.connect(lambda: self.sign_raw_transaction(tx, tx.inputs, dialog))
                l.addWidget(b, 4, 1)
            else:
                l.addWidget(QLabel(_("Wallet is de-seeded, can't sign.")), 4,1)
        else:
            l.addWidget(QLabel(_("Signed")), 3,1)
            b = QPushButton("Broadcast transaction")
            def broadcast(tx):
                result, result_message = self.gui.main_window.wallet.sendtx( tx )
                if result:
                    self.gui.main_window.show_message(_("Transaction successfully sent:")+' %s' % (result_message))
                    if dialog:
                        dialog.done(0)
                else:
                    self.gui.main_window.show_message(_("There was a problem sending your transaction:") + '\n %s' % (result_message))
            b.clicked.connect(lambda: broadcast( tx ))
            l.addWidget(b,4,1)
    
        closeButton = QPushButton(_("Close"))
        closeButton.clicked.connect(lambda: dialog.done(0))
        l.addWidget(closeButton, 4,2)

        dialog.exec_()

    def do_protect(self, func, args):
        if self.gui.main_window.wallet.use_encryption:
            password = self.gui.main_window.password_dialog()
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
            self.gui.main_window.wallet.signrawtransaction(tx, input_info, [], password)
            txtext = json.dumps(tx.as_dict()).replace(' ', '')
            self.show_tx_qrcode(txtext, 'Signed Transaction')
        except Exception as e:
            self.gui.main_window.show_message(str(e))


    def fill_from_qr(self):
        qrcode = parse_uri(self.scan_qr())
        if not qrcode:
            return

        if 'address' in qrcode:
            self.gui.main_window.payto_e.setText(qrcode['address'])
        if 'amount' in qrcode:
            self.gui.main_window.amount_e.setText(str(qrcode['amount']))
        if 'label' in qrcode:
            self.gui.main_window.message_e.setText(qrcode['label'])
        if 'message' in qrcode:
            self.gui.main_window.message_e.setText("%s (%s)" % (self.gui.main_window.message_e.text(), qrcode['message']))
                
    def video_device(self):
        device = self.config.get("video_device", "default")
        if device == 'default':
            device = ''
        return device

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)
    
    def _find_system_cameras(self):
        device_root = "/sys/class/video4linux"
        devices = {} # Name -> device
        if os.path.exists(device_root):
            for device in os.listdir(device_root):
                name = open(os.path.join(device_root, device, 'name')).read()
                devices[name] = os.path.join("/dev",device)
        return devices

    def settings_dialog(self):
        system_cameras = self._find_system_cameras()

        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel("Choose a video device:"),0,0)

        # Create a combo box with the available video devices:
        combo = QComboBox()

        # on change trigger for video device selection, makes the
        # manual device selection only appear when needed:
        def on_change(x):
            combo_text = str(combo.itemText(x))
            combo_data = combo.itemData(x)
            if combo_text == "Manually specify a device":
                custom_device_label.setVisible(True)
                self.video_device_edit.setVisible(True)
                if self.config.get("video_device") == "default":
                    self.video_device_edit.setText("")
                else:
                    self.video_device_edit.setText(self.config.get("video_device"))
            else:
                custom_device_label.setVisible(False)
                self.video_device_edit.setVisible(False)
                self.video_device_edit.setText(combo_data.toString())

        # on save trigger for the video device selection window,
        # stores the chosen video device on close.
        def on_save():
            device = str(self.video_device_edit.text())
            self.config.set_key("video_device", device)
            d.accept()

        custom_device_label = QLabel("Video device: ")
        custom_device_label.setVisible(False)
        layout.addWidget(custom_device_label,1,0)
        self.video_device_edit = QLineEdit()
        self.video_device_edit.setVisible(False)
        layout.addWidget(self.video_device_edit, 1,1,2,2)
        combo.currentIndexChanged.connect(on_change)

        combo.addItem("Default","default")
        for camera, device in system_cameras.items():
            combo.addItem(camera, device)
        combo.addItem("Manually specify a device",self.config.get("video_device"))

        # Populate the previously chosen device:
        index = combo.findData(self.config.get("video_device"))
        combo.setCurrentIndex(index)

        layout.addWidget(combo,0,1)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(on_save)
        layout.addWidget(self.accept,4,2)

        if d.exec_():
          return True
        else:
          return False



def parse_uri(uri):
    if ':' not in uri:
        # It's just an address (not BIP21)
        return {'address': uri}

    if '//' not in uri:
        # Workaround for urlparse, it don't handle bitcoin: URI properly
        uri = uri.replace(':', '://')
        
    uri = urlparse(uri)
    result = {'address': uri.netloc} 
    
    if uri.query.startswith('?'):
        params = parse_qs(uri.query[1:])
    else:
        params = parse_qs(uri.query)    

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
    
    
