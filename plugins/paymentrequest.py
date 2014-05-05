from PyQt4.QtGui import *
from PyQt4.QtCore import *
import hashlib
import httplib
import os.path
import re
import sys
import threading
import time
import traceback
import urllib2

try:
    from lib import paymentrequest_pb2
    import urlparse
    from M2Crypto import X509
    import requests
    loaded_libs = True
except ImportError as e:
    loaded_libs = False

from electrum.plugins import BasePlugin
from electrum.i18n import _
from electrum.bitcoin import is_valid
from electrum_gui.qt import ok_cancel_buttons

### functions from pybitcointools:

def bin_dbl_sha256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()

def get_code_string(base):
    if base == 2: return '01'
    elif base == 10: return '0123456789'
    elif base == 16: return '0123456789abcdef'
    elif base == 32: return 'abcdefghijklmnopqrstuvwxyz2345657'
    elif base == 58: return '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    elif base == 256: return ''.join([chr(x) for x in range(256)])
    else: raise ValueError("Invalid base!")

def bin_to_b58check(inp,magicbyte=0):
    inp_fmtd = chr(int(magicbyte)) + inp
    leadingzbytes = len(re.match('^\x00*',inp_fmtd).group(0))
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return '1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)

def changebase(string,frm,to,minlen=0):
    if frm == to: return lpad(string,minlen)
    return encode(decode(string,frm),to,minlen)

def lpad(msg,symbol,length):
    if len(msg) >= length: return msg
    return symbol * (length - len(msg)) + msg

def encode(val,base,minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result = ""
    while val > 0:
        result = code_string[val % base] + result
        val /= base
    return lpad(result,code_string[0],minlen)

def decode(string,base):
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 16: string = string.lower()
    while len(string) > 0:
        result *= base
        result += code_string.find(string[0])
        string = string[1:]
    return result

def script_to_address(script,vbyte=0):
    if re.match('^[0-9a-fA-F]*$',script):
        script = script.decode('hex')
    if script[:3] == '\x76\xa9\x14' and script[-2:] == '\x88\xac' and len(script) == 25:
        return bin_to_b58check(script[3:-2],vbyte) # pubkey hash addresses
    else:
        return bin_to_b58check(script[2:-1],5) # BIP0016 scripthash addresses

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*',inp).group(0))
    data = '\x00' * leadingzbytes + changebase(inp,58,256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

def b58check_to_hex(inp): return b58check_to_bin(inp).encode('hex')

def mk_pubkey_script(addr): # Keep the auxiliary functions around for altcoins' sake
    return '76a914' + b58check_to_hex(addr) + '88ac'

def address_to_script(addr):
    if addr[0] == '3': return mk_scripthash_script(addr)
    else: return mk_pubkey_script(addr)
### END PyBitcoinTools functions



class Plugin(BasePlugin):
    def fullname(self):
        return _("Payment Request")
    def description(self):
        return _("BIP0070 Payment Request Support - required python modules: M2Crypto, protobuf, requests, urlparse")

    def __init__(self,a,b):
        BasePlugin.__init__(self,a,b)

    def is_available(self):
        return loaded_libs

    def enable(self):
        return BasePlugin.enable(self)

    def init(self):
        self.win = self.gui.main_window
        self.lock = threading.Lock()

    def do_payment_request(self, r, payment_req_complete):
        u = urlparse.urlparse(urllib2.unquote(r))

        domain = u.netloc

        try:
            if u.scheme == 'http':
                connection = httplib.HTTPConnection(u.netloc)
                connection.request("GET",u.geturl(),headers={'Accept': 'application/bitcoin-paymentrequest', 'User-Agent': 'Electrum'})
                resp = connection.getresponse()
            elif u.scheme == 'https':
                connection = httplib.HTTPSConnection(u.netloc)
                connection.request("GET",u.geturl(),headers={'Accept': 'application/bitcoin-paymentrequest', 'User-Agent': 'Electrum'})
                resp = connection.getresponse()
            else:
                return
        except Exception:
            return

        r = resp.read()

        paymntreq = paymentrequest_pb2.PaymentRequest()
        paymntreq.ParseFromString(r)

        sig = paymntreq.signature

        cert = paymentrequest_pb2.X509Certificates()
        cert.ParseFromString(paymntreq.pki_data)
        cert_num = len(cert.certificate)

        x509_1 = X509.load_cert_der_string(cert.certificate[0])
        if domain != x509_1.get_subject().CN:
###TODO: check for subject alt names
###       check for wildcards
            self.win.show_message(_("ERROR: Certificate Subject Domain Mismatch"))
            return

        x509 = []
        CA_OU = ''
        trusted_ca = False

        if cert_num > 1:
            for i in range(cert_num - 1):
                x509.append(X509.load_cert_der_string(cert.certificate[i+1]))
                if x509[i].check_ca() == 0:
                    self.win.show_message(_("ERROR: Supplied CA Certificate Error"))
                    return
            for i in range(cert_num - 1):
                if i == 0:
                    if x509_1.verify(x509[i].get_pubkey()) != 1:
                        self.win.show_message(_("ERROR: Certificate not Signed by Provided CA Certificate Chain"))
                        return
                else:
                    if x509[i-1].verify(x509[i].get_pubkey()) != 1:
                        self.win.show_message(_("ERROR: CA Certificate not Signed by Provided CA Certificate Chain"))
                        return
            try:
                ca_path = os.path.join(self.win.config.path,'ca/ca-bundle.crt')
                ca_f = open(ca_path, 'r')
                trusted_ca = True
            except Exception:
                self.win.show_message(_("ERROR: Could not open ca-bundle.crt file.\nca-bundle.crt file should be placed in ~/.electrum/ca/ca-bundle.crt\nDocumentation on how to download or create the file here: http://curl.haxx.se/docs/caextract.html\nPayment will continue with manual verification."))

            if trusted_ca:
                supplied_CA_fingerprint = x509[cert_num-2].get_fingerprint()
                supplied_CA_CN = x509[cert_num-2].get_subject().CN
                CA_match = False
                c = ""
                for line in ca_f:
                    if line == "-----BEGIN CERTIFICATE-----\n":
                        c = "-----BEGIN CERTIFICATE-----\n"
                    else:
                        c += line
                    if line == "-----END CERTIFICATE-----\n":
                        x = X509.load_cert_string(c)
                        CA_OU = x.get_subject().OU
                        if x.get_fingerprint() == supplied_CA_fingerprint:
                            CA_match = True
                            if x.get_subject().CN != supplied_CA_CN:
                                self.win.show_message(_("ERROR: Trusted CA CN Mismatch; however CA has trusted fingerprint\nPayment will continue with manual verification."))
                            break
                ca_f.close()
                if not CA_match:
                    a = self.win.question(_("ERROR: Supplied CA Not Found in Trusted CA Store. Continue with manual verification?"))
                    if not a:
                        return
        else:
            self.win.show_message(_("ERROR: CA Certificate Chain Not Provided by Payment Processor"))
            return

        paymntreq.signature = ''
        s = paymntreq.SerializeToString()
        pubkey_1 = x509_1.get_pubkey()

        if paymntreq.pki_type == "x509+sha256":
            pubkey_1.reset_context(md="sha256")
        elif paymntreq.pki_type == "x509+sha1":
            pubkey_1.reset_context(md="sha1")
        else:
            self.win.show_message(_("ERROR: Unsupported PKI Type for Message Signature"))
            return

        pubkey_1.verify_init()
        pubkey_1.verify_update(s)
        if pubkey_1.verify_final(sig) != 1:
            self.win.show_message(_("ERROR: Invalid Signature for Payment Request Data"))
            return

        ### SIG Verified

        pay_det = paymentrequest_pb2.PaymentDetails()
        pay_det.ParseFromString(paymntreq.serialized_payment_details)

        if pay_det.expires and pay_det.expires < int(time.time()):
            self.win.show_message(_("ERROR: Payment Request has Expired."))
            return

        total_amount = 0
        o_addrs = []
        o_amounts = []

        for o in pay_det.outputs:
            total_amount += o.amount
            o_addrs.append(script_to_address(o.script))
            o_amounts.append(o.amount)

        d = QDialog()
        d.setWindowTitle(_("Received Payment Request"))

        vbox = QVBoxLayout(d)
        layout = QGridLayout()

        layout.addWidget(QLabel(_('Payment Request Verified Domain: ')), 0, 0)
        layout.addWidget(QLabel(domain), 0, 1)

        layout.addWidget(QLabel(_('Total Payment Amount: ')), 1, 0)
        layout.addWidget(QLabel(self.win.format_amount(total_amount) + " " + self.win.base_unit()), 1, 1)

        layout.addWidget(QLabel(_('Payment Memo: ')), 2, 0)
        layout.addWidget(QLabel(pay_det.memo),2,1)

        if trusted_ca:
            layout.addWidget(QLabel(_('Signed By Trusted CA: ')), 3, 0)
            layout.addWidget(QLabel(CA_OU),3,1)
        else:
            warn = QLabel(_('WARNING: No Trusted CA Store Loaded for Verification'))
            palette = QPalette()
            palette.setColor(QPalette.Foreground,Qt.red)
            warn.setPalette(palette)
            layout.addWidget(warn, 3, 1)

        vbox.addLayout(layout)
        vbox.addLayout(ok_cancel_buttons(d))

        if not d.exec_():
            return

        sendable = self.win.get_sendable_balance()

        ### TODO: Calculate fee
        # or allow enter fee
        fee = 1000

        if total_amount > (sendable - fee):
            self.win.show_message(_("ERROR: Not Enough Funds Available"))
            return

        inputs, total, fee = self.win.wallet.choose_tx_inputs(total_amount, fee, len(o_addrs) + 1, self.win.get_payment_sources())

        if not inputs:
            self.win.show_message(_("ERROR: Could not calculate inputs for transaction."))
            return

        for o in o_addrs:
            if not is_valid(o):
                self.win.show_message(_("ERROR: Invalid Address Provided for Payment."))
                return

        confirm_string = "Confirm Addresses and Amounts: "
        for i in range(len(o_addrs)):
            confirm_string += "\n" + str(o_addrs[i]) + ": " + self.win.format_amount(o_amounts[i]) + " " + self.win.base_unit()

        confirm_string += "\nFee: " + self.win.format_amount(fee) + " " + self.win.base_unit()

        if not self.win.question(confirm_string):
            return


        send_outputs = []
        for i in range(len(o_addrs)):
            send_outputs.append((o_addrs[i],o_amounts[i]))

        dom = self.win.get_payment_sources()
        try:
            tx = self.win.wallet.make_unsigned_transaction(send_outputs, fee, None, dom)
            tx.error = None
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.win.show_message(str(e))
            return

        self.send_payment_tx(tx, fee, pay_det.memo)

        #Wait for signing/sending transaction to complete
        time.sleep(0.3)
        with self.lock:
            payment_req_complete[0] = True

        if pay_det.payment_url:
            paymnt = paymentrequest_pb2.Payment()

            paymnt.merchant_data = pay_det.merchant_data
            paymnt.transactions.append(str(self.win.signed_tx))

            refund_addrs = self.win.wallet.get_account_addresses(0)
            refund_to = refund_addrs[len(refund_addrs)-1]

            ref_out = paymnt.refund_to.add()
            ref_out.script = address_to_script(refund_to)

            paymnt.memo = "Paid via Electrum BIP0070 Plugin"

            pm = paymnt.SerializeToString()

            payurl = urlparse.urlparse(pay_det.payment_url)
            try:
                try:
                    ca_path = os.path.join(self.win.config.path,'ca/ca-bundle.crt')
                    r = requests.post(payurl.geturl(), data=pm, headers={'Content-Type':'application/bitcoin-payment','Accept':'application/bitcoin-paymentack','User-Agent':'Electrum'}, verify=ca_path)
                except Exception:
                    pass
                else:
                    r = requests.post(payurl.geturl(), data=pm, headers={'Content-Type':'application/bitcoin-payment','Accept':'application/bitcoin-paymentack','User-Agent':'Electrum'}, verify=False)
            except Exception as e:
                print e
                self.win.show_message("Payment Message/PaymentACK Failed")
                return
            try:
                paymntack = paymentrequest_pb2.PaymentACK()
                paymntack.ParseFromString(r.content)
                self.win.show_message("PaymentACK message received: %s" % paymntack.memo)
            except Exception:
                self.win.show_message(_("PaymentACK could not be processed. Payment was sent; please manually verify that payment was received."))


    def do_protect(self, func, args):
          if self.win.wallet.use_encryption:
              password = self.win.password_dialog()
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
    def send_payment_tx(self, tx, fee, label, password):
        def sign_thread():
            with self.lock:
                time.sleep(0.1)
                keypairs = {}
                self.win.wallet.add_keypairs_from_wallet(tx, keypairs, password)
                self.win.wallet.sign_transaction(tx, keypairs, password)
                self.win.signed_tx = tx
                self.win.signed_tx_data = (tx, fee, label)
                self.win.emit(SIGNAL('send_tx2'))

        # sign the tx
        dialog = self.win.waiting_dialog('Signing..')
        self.win.tx_wait_dialog = dialog
        threading.Thread(target=sign_thread).start()

