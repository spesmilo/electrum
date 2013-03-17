from electrum.util import print_error
from urlparse import urlparse, parse_qs
from PyQt4.QtGui import QPushButton
from electrum_gui.i18n import _

try:
    import zbar
except ImportError:
    zbar = None

from electrum_gui import BasePlugin
class Plugin(BasePlugin):

    def __init__(self, gui):
        BasePlugin.__init__(self, gui, 'qrscans', 'QR scans', "QR Scans.\nInstall the zbar package to enable this plugin")
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
                return parse_uri(r.data)
        

    def fill_from_qr(self):
        qrcode = self.scan_qr()
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
    
    
