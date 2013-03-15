from electrum.util import print_error
from urlparse import urlparse, parse_qs

try:
    import zbar
except ImportError:
    zbar = None



def init(gui):
    if is_enabled():
        gui.set_hook('create_send_tab', create_send_tab)
    else:
        gui.unset_hook('create_send_tab', create_send_tab)

def get_info():
    return 'QR scans', "QR Scans.\nInstall the zbar package to enable this plugin"

def is_enabled():
    return is_available()

def toggle(gui):
    return is_enabled()


def is_available():
    if not zbar:
        return False

    try:
        proc = zbar.Processor()
        proc.init()
    except zbar.SystemError:
        # Cannot open video device
        return False

    return True

def scan_qr():
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



def fill_from_qr(self):
    qrcode = scan_qr()
    if 'address' in qrcode:
        self.payto_e.setText(qrcode['address'])
    if 'amount' in qrcode:
        self.amount_e.setText(str(qrcode['amount']))
    if 'label' in qrcode:
        self.message_e.setText(qrcode['label'])
    if 'message' in qrcode:
        self.message_e.setText("%s (%s)" % (self.message_e.text(), qrcode['message']))
                

def create_send_tab(gui, grid):
    if is_available():
        b = QPushButton(_("Scan QR code"))
        b.clicked.connect(lambda: fill_from_qr(gui))
        grid.addWidget(b, 1, 5)



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
    
    
