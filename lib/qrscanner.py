from util import print_error

try:
    import zbar
except ImportError:    
    print_error("Install zbar package to enable QR scans")
    zbar = None

from urlparse import urlparse, parse_qs

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
    
    
