#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2014 Thomas Voegtlin
# Copyright (C) 2019 Calin Culianu <calin.culianu@gmail.com>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import hashlib
import sys
import time
import traceback
import json
import requests
import urllib.parse
import dateutil.parser
import threading
import zlib
from collections import namedtuple

try:
    from . import paymentrequest_pb2 as pb2
except ImportError:
    sys.exit("Error: could not find paymentrequest_pb2.py. Create it with 'protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto'")

from . import bitcoin
from . import version
from . import util
from . import transaction
from . import x509
from . import rsakey

from .address import Address, PublicKey
from .bitcoin import TYPE_ADDRESS
from .util import print_error, bh2u, bfh, PrintError
from .util import FileImportFailed, FileImportFailedEncrypted
from .transaction import Transaction

def _(message): return message

# status of payment requests
PR_UNPAID  = 0
PR_EXPIRED = 1
PR_UNKNOWN = 2     # sent but not propagated
PR_PAID    = 3     # send and propagated

pr_tooltips = {
    PR_UNPAID:_('Pending'),
    PR_UNKNOWN:_('Unknown'),
    PR_PAID:_('Paid'),
    PR_EXPIRED:_('Expired')
}

del _

REQUEST_HEADERS = {'Accept': 'application/bitcoincash-paymentrequest', 'User-Agent': 'Electron-Cash'}
ACK_HEADERS = {'Content-Type':'application/bitcoincash-payment','Accept':'application/bitcoincash-paymentack','User-Agent':'Electron-Cash'}

ca_path = requests.certs.where()
ca_list = None
ca_keyID = None

def load_ca_list():
    global ca_list, ca_keyID
    if ca_list is None:
        ca_list, ca_keyID = x509.load_certificates(ca_path)


def get_payment_request(url):
    data = error = None
    try:
        u = urllib.parse.urlparse(url)
    except ValueError as e:
        error = str(e)
    else:
        if u.scheme in ('https',) and u.netloc.lower().endswith('bitpay.com'):
            # Use BitPay 2.0 JSON-based API -- https only
            return get_payment_request_bitpay20(url)

        #.. else, try regular BIP70
        if u.scheme in ['http', 'https']:
            try:
                response = requests.request('GET', url, headers=REQUEST_HEADERS)
                response.raise_for_status()
                # Guard against `bitcoincash:`-URIs with invalid payment request URLs
                if "Content-Type" not in response.headers \
                or response.headers["Content-Type"] != "application/bitcoincash-paymentrequest":
                    error = "payment URL not pointing to a bitcoincash payment request handling server"
                else:
                    data = response.content
                print_error('fetched payment request', url, len(response.content))
            except requests.exceptions.RequestException as e:
                error = str(e)
        elif u.scheme == 'file':
            try:
                with open(u.path, 'r', encoding='utf-8') as f:
                    data = f.read()
            except IOError:
                error = "payment URL not pointing to a valid file"
        else:
            error = f"unknown scheme: '{u.scheme}'"

    return PaymentRequest(data, error)


class PaymentRequest:

    def __init__(self, data, error=None):
        self.raw = data
        self.error = error
        self.parse(data)
        self.requestor = None # known after verify
        self.tx = None

    def __str__(self):
        return str(self.raw)

    def parse(self, r):
        if self.error:
            return
        self.id = bh2u(bitcoin.sha256(r)[0:16])
        try:
            self.data = pb2.PaymentRequest()
            self.data.ParseFromString(r)
        except:
            self.error = "cannot parse payment request"
            return
        self.details = pb2.PaymentDetails()
        self.details.ParseFromString(self.data.serialized_payment_details)
        self.outputs = []
        for o in self.details.outputs:
            addr = transaction.get_address_from_output_script(o.script)[1]
            self.outputs.append((TYPE_ADDRESS, addr, o.amount))
        self.memo = self.details.memo
        self.payment_url = self.details.payment_url

    def is_pr(self):
        return self.get_amount() != 0

    def verify(self, contacts):
        if self.error:
            return False
        if not self.raw:
            self.error = "Empty request"
            return False
        pr = pb2.PaymentRequest()
        try:
            pr.ParseFromString(self.raw)
        except:
            self.error = "Error: Cannot parse payment request"
            return False
        if not pr.signature:
            # the address will be dispayed as requestor
            self.requestor = None
            return True
        if pr.pki_type in ["x509+sha256", "x509+sha1"]:
            return self.verify_x509(pr)
        elif pr.pki_type in ["dnssec+btc", "dnssec+ecdsa"]:
            return self.verify_dnssec(pr, contacts)
        else:
            self.error = "ERROR: Unsupported PKI Type for Message Signature"
            return False

    def verify_x509(self, paymntreq):
        load_ca_list()
        if not ca_list:
            self.error = "Trusted certificate authorities list not found"
            return False
        cert = pb2.X509Certificates()
        cert.ParseFromString(paymntreq.pki_data)
        # verify the chain of certificates
        try:
            x, ca = verify_cert_chain(cert.certificate)
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.error = str(e)
            return False
        # get requestor name
        self.requestor = x.get_common_name()
        if self.requestor.startswith('*.'):
            self.requestor = self.requestor[2:]
        # verify the BIP70 signature
        pubkey0 = rsakey.RSAKey(x.modulus, x.exponent)
        sig = paymntreq.signature
        paymntreq.signature = b''
        s = paymntreq.SerializeToString()
        sigBytes = bytearray(sig)
        msgBytes = bytearray(s)
        if paymntreq.pki_type == "x509+sha256":
            hashBytes = bytearray(hashlib.sha256(msgBytes).digest())
            verify = pubkey0.verify(sigBytes, x509.PREFIX_RSA_SHA256 + hashBytes)
        elif paymntreq.pki_type == "x509+sha1":
            verify = pubkey0.hashAndVerify(sigBytes, msgBytes)
        if not verify:
            self.error = "ERROR: Invalid Signature for Payment Request Data"
            return False
        ### SIG Verified
        self.error = 'Signed by Trusted CA: ' + ca.get_common_name()
        return True

    def verify_dnssec(self, pr, contacts):
        sig = pr.signature
        alias = util.to_string(pr.pki_data)
        try:
            info = contacts.resolve(alias)
        except RuntimeWarning as e:
            # Failed to resolve openalias or contact
            self.error = ' '.join(e.args)
            return False
        except Exception as e:
            # misc other parse error (bad address, etc)
            self.error = str(e)
            return False
        if info.get('validated') is not True:
            self.error = "Alias verification failed (DNSSEC)"
            return False
        if pr.pki_type == "dnssec+btc":
            self.requestor = alias
            address = info.get('address')
            pr.signature = b''
            message = pr.SerializeToString()
            if bitcoin.verify_message(address, sig, message):
                self.error = 'Verified with DNSSEC'
                return True
            else:
                self.error = "verify failed"
                return False
        else:
            self.error = "unknown algo"
            return False

    def has_expired(self):
        return self.details.expires and self.details.expires < int(time.time())

    def get_expiration_date(self):
        return self.details.expires

    def get_amount(self):
        return sum(map(lambda x:x[2], self.outputs))

    def get_address(self):
        o = self.outputs[0]
        assert o[0] == TYPE_ADDRESS
        return o[1].to_ui_string()

    def get_requestor(self):
        return self.requestor if self.requestor else self.get_address()

    def get_verify_status(self):
        return self.error if self.requestor else "No Signature"

    def get_memo(self):
        return self.memo

    def get_payment_url(self):
        return self.details.payment_url

    def get_dict(self):
        return {
            'requestor': self.get_requestor(),
            'memo':self.get_memo(),
            'exp': self.get_expiration_date(),
            'amount': self.get_amount(),
            'signature': self.get_verify_status(),
            'txid': self.tx,
            'outputs': self.get_outputs(),
            'payment_url': self.get_payment_url()
        }

    def get_id(self):
        return self.id if self.requestor else self.get_address()

    def get_outputs(self):
        return self.outputs[:]

    def send_payment(self, raw_tx, refund_addr):
        pay_det = self.details
        if not self.details.payment_url:
            return False, "no url"  # note caller is expecting this exact string in the "no payment url specified" case. see main_window.py and/or ios_native/gui.py
        paymnt = pb2.Payment()
        paymnt.merchant_data = pay_det.merchant_data
        paymnt.transactions.append(bfh(raw_tx))
        ref_out = paymnt.refund_to.add()
        ref_out.script = bfh(transaction.Transaction.pay_script(refund_addr))
        paymnt.memo = "Paid using Electron Cash"
        pm = paymnt.SerializeToString()
        payurl = urllib.parse.urlparse(pay_det.payment_url)
        try:
            r = requests.post(payurl.geturl(), data=pm, headers=ACK_HEADERS, verify=ca_path)
        except requests.exceptions.RequestException as e:
            return False, str(e)
        if r.status_code != 200:
            # Propagate 'Bad request' (HTTP 400) messages to the user since they
            # contain valuable information.
            if r.status_code == 400:
                return False, (r.reason + ": " + r.content.decode('UTF-8'))
            # Some other errors might display an entire HTML document.
            # Hide those and just display the name of the error code.
            return False, r.reason
        try:
            paymntack = pb2.PaymentACK()
            paymntack.ParseFromString(r.content)
        except Exception:
            return False, "PaymentACK could not be processed. Payment was sent; please manually verify that payment was received."
        print("PaymentACK message received: %s" % paymntack.memo)
        return True, paymntack.memo

    def serialize(self):
        ''' Returns bytes '''
        return self.raw or b''

    @classmethod
    def deserialize(cls, ser):
        return cls(ser)

    def export_file_data(self):
        ''' Returns bytes suitable to be saved to a file '''
        return self.serialize()

    @classmethod
    def export_file_ext(cls):
        return 'bip70'


def make_unsigned_request(req):
    from .transaction import Transaction
    from .address import Address
    addr = req['address']
    time = req.get('time', 0)
    exp = req.get('exp', 0)
    payment_url = req.get('payment_url')
    if time and type(time) != int:
        time = 0
    if exp and type(exp) != int:
        exp = 0
    amount = req['amount']
    if amount is None:
        amount = 0
    memo = req['memo']
    if not isinstance(addr, Address):
        addr = Address.from_string(addr)
    script = bfh(Transaction.pay_script(addr))
    outputs = [(script, amount)]
    pd = pb2.PaymentDetails()
    for script, amount in outputs:
        pd.outputs.add(amount=amount, script=script)
    pd.time = time
    pd.expires = time + exp if exp else 0
    pd.memo = memo
    if payment_url:
        pd.payment_url = payment_url
    pr = pb2.PaymentRequest()

    # Note: We explicitly set this again here to 1 (default was already 1).
    # The reason we need to do this is because __setattr__ for this class
    # will trigger the Serialization to be 4 bytes of this field, rather than 2,
    # if it was explicitly set programmatically.
    #
    # This works around possible bugs with google protobuf for Javascript
    # seen in the field -- in particular bitcoin.com was rejecting our BIP70 files
    # because payment_details_version needed to be 4 bytes, not 2.
    # Forcing the encoding to 4 bytes for payment_details_version fixed the
    # rejection.  This workaround is likely needed due to bugs in the protobuf.js
    # library.
    pr.payment_details_version = int(pr.payment_details_version)

    pr.serialized_payment_details = pd.SerializeToString()
    pr.signature = util.to_bytes('')
    return pr


def sign_request_with_alias(pr, alias, alias_privkey):
    pr.pki_type = 'dnssec+btc'
    pr.pki_data = util.to_bytes(alias)
    message = pr.SerializeToString()
    _typ, raw_key, compressed = bitcoin.deserialize_privkey(alias_privkey)
    ec_key = bitcoin.regenerate_key(raw_key)
    pr.signature = ec_key.sign_message(message, compressed)


def verify_cert_chain(chain):
    """ Verify a chain of certificates. The last certificate is the CA"""
    load_ca_list()
    # parse the chain
    cert_num = len(chain)
    x509_chain = []
    for i in range(cert_num):
        x = x509.X509(bytearray(chain[i]))
        x509_chain.append(x)
        if i == 0:
            x.check_date()
        else:
            if not x.check_ca():
                raise BaseException("ERROR: Supplied CA Certificate Error")
    if not cert_num > 1:
        raise BaseException("ERROR: CA Certificate Chain Not Provided by Payment Processor")
    # if the root CA is not supplied, add it to the chain
    ca = x509_chain[cert_num-1]
    if ca.getFingerprint() not in ca_list:
        keyID = ca.get_issuer_keyID()
        f = ca_keyID.get(keyID)
        if f:
            root = ca_list[f]
            x509_chain.append(root)
        else:
            raise BaseException("Supplied CA Not Found in Trusted CA Store.")
    # verify the chain of signatures
    cert_num = len(x509_chain)
    for i in range(1, cert_num):
        x = x509_chain[i]
        prev_x = x509_chain[i-1]
        algo, sig, data = prev_x.get_signature()
        sig = bytearray(sig)
        pubkey = rsakey.RSAKey(x.modulus, x.exponent)
        if algo == x509.ALGO_RSA_SHA1:
            verify = pubkey.hashAndVerify(sig, data)
        elif algo == x509.ALGO_RSA_SHA256:
            hashBytes = bytearray(hashlib.sha256(data).digest())
            verify = pubkey.verify(sig, x509.PREFIX_RSA_SHA256 + hashBytes)
        elif algo == x509.ALGO_RSA_SHA384:
            hashBytes = bytearray(hashlib.sha384(data).digest())
            verify = pubkey.verify(sig, x509.PREFIX_RSA_SHA384 + hashBytes)
        elif algo == x509.ALGO_RSA_SHA512:
            hashBytes = bytearray(hashlib.sha512(data).digest())
            verify = pubkey.verify(sig, x509.PREFIX_RSA_SHA512 + hashBytes)
        else:
            raise BaseException("Algorithm not supported")
            util.print_error(self.error, algo.getComponentByName('algorithm'))
        if not verify:
            raise BaseException("Certificate not Signed by Provided CA Certificate Chain")

    return x509_chain[0], ca


def check_ssl_config(config):
    from . import pem
    key_path = config.get('ssl_privkey')
    cert_path = config.get('ssl_chain')
    with open(key_path, 'r', encoding='utf-8') as f:
        params = pem.parse_private_key(f.read())
    with open(cert_path, 'r', encoding='utf-8') as f:
        s = f.read()
    bList = pem.dePemList(s, "CERTIFICATE")
    # verify chain
    x, ca = verify_cert_chain(bList)
    # verify that privkey and pubkey match
    privkey = rsakey.RSAKey(*params)
    pubkey = rsakey.RSAKey(x.modulus, x.exponent)
    assert x.modulus == params[0]
    assert x.exponent == params[1]
    # return requestor
    requestor = x.get_common_name()
    if requestor.startswith('*.'):
        requestor = requestor[2:]
    return requestor

def sign_request_with_x509(pr, key_path, cert_path):
    from . import pem
    with open(key_path, 'r', encoding='utf-8') as f:
        params = pem.parse_private_key(f.read())
        privkey = rsakey.RSAKey(*params)
    with open(cert_path, 'r', encoding='utf-8') as f:
        s = f.read()
        bList = pem.dePemList(s, "CERTIFICATE")
    certificates = pb2.X509Certificates()
    certificates.certificate.extend(map(bytes, bList))
    pr.pki_type = 'x509+sha256'
    pr.pki_data = util.to_bytes(certificates.SerializeToString())
    msgBytes = bytearray(pr.SerializeToString())
    hashBytes = bytearray(hashlib.sha256(msgBytes).digest())
    sig = privkey.sign(x509.PREFIX_RSA_SHA256 + hashBytes)
    pr.signature = bytes(sig)


def serialize_request(req):
    pr = make_unsigned_request(req)
    signature = req.get('sig')
    requestor = req.get('name')
    if requestor and signature:
        pr.signature = bfh(signature)
        pr.pki_type = 'dnssec+btc'
        pr.pki_data = util.to_bytes(requestor)
    return pr


def make_request(config, req):
    pr = make_unsigned_request(req)
    key_path = config.get('ssl_privkey')
    cert_path = config.get('ssl_chain')
    if key_path and cert_path:
        sign_request_with_x509(pr, key_path, cert_path)
    return pr



class InvoiceStore(object):

    def __init__(self, storage):
        self.storage = storage
        self.invoices = {}
        self.paid = {}
        d = self.storage.get('invoices2', b'?')
        if d == b'?':
            # new format not found, use old format (upgrade)
            d = self.storage.get('invoices', {})
        self.load(d)

    def set_paid(self, pr, txid):
        pr.tx = txid
        self.paid[txid] = pr.get_id()

    def load(self, d):
        for k, v in d.items():
            try:
                pr = None
                raw = bfh(v.get('hex'))
                try:
                    # First try BitPay 2.0 style PR -- this contains compressed raw bytes of the headers & json associated with the request; will raise if wrong format
                    pr = PaymentRequest_BitPay20.deserialize(raw)
                except:
                    pass
                if not pr:
                    # Lastly, try the BIP70 style PR; this won't raise if bad format
                    pr = PaymentRequest.deserialize(raw)
                pr.tx = v.get('txid')
                pr.requestor = v.get('requestor')
                self.invoices[k] = pr
                if pr.tx:
                    self.paid[pr.tx] = k
            except:
                continue

    def import_file(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                d = json.loads(f.read())
                self.load(d)
        except json.decoder.JSONDecodeError:
            traceback.print_exc(file=sys.stderr)
            raise FileImportFailedEncrypted()
        except BaseException:
            traceback.print_exc(file=sys.stdout)
            raise FileImportFailed()
        self.save()

    def save(self):
        l = {}
        for k, pr in self.invoices.items():
            l[k] = {
                'hex': bh2u(pr.serialize()),
                'requestor': pr.requestor,
                'txid': pr.tx
            }
        self.storage.put('invoices2', l)
        self.storage.put('invoices', None)  # delete old invoice format to save space; caveat: older EC versions will not see invoices saved by newer versions anymore.

    def get_status(self, key):
        pr = self.get(key)
        if pr is None:
            print_error("[InvoiceStore] get_status() can't find pr for", key)
            return
        if pr.tx is not None:
            return PR_PAID
        if pr.has_expired():
            return PR_EXPIRED
        return PR_UNPAID

    def add(self, pr):
        key = pr.get_id()
        self.invoices[key] = pr
        self.save()
        return key

    def remove(self, key):
        paid_list = self.paid.items()
        for p in paid_list:
            if p[1] == key:
                self.paid.pop(p[0])
                break
        self.invoices.pop(key)
        self.save()

    def get(self, k):
        return self.invoices.get(k)

    def sorted_list(self):
        # sort
        return self.invoices.values()

    def unpaid_invoices(self):
        return [v for k, v in self.invoices.items()
                if self.get_status(k) not in (PR_PAID, None)]

# -----------------------------------------------------------------------------
''' BitPay 2.0 JSON-based HTTP Payment Protocol, replaces BIP70 for BitPay only.
Includes a scheme to verify the payment request using Bitcoin public keys
rather than x509 which is what BIP70 used. '''

class ResponseError(Exception):
    ''' Contains the exact text of the bad response error message from BitPay'''

class PaymentRequest_BitPay20(PaymentRequest, PrintError):
    ''' Work-alike to the existing BIP70 PaymentRequest class.
    Wraps payment requests based on the new BitPay 2.0 JSON API.'''

    # Extra headers we attach to requests we send to BitPay, so they may
    # track us as a 'partner' (we actually get a small amount of revenue this way).
    HEADERS = { 'BP_PARTNER'         : 'ELECTRONCASH',
                'BP_PARTNER_VERSION' : 'V' + version.PACKAGE_VERSION,
                'User-Agent'         : 'Electron-Cash' }

    Details = namedtuple('BitPay20Details', 'outputs, memo, payment_url, time, expires, network, currency, required_fee_rate')

    class Raw:
        __slots__ = ('status_code', 'headers', 'text', 'url')
        ser_prefix = b'BITPAY2.0_ZCOMPRESSED_'
        def __init__(self, **kwargs):
            resp = kwargs.get('response')
            if resp:
                if not isinstance(resp, requests.Response):
                    raise ValueError("Expected a Response object in PaymentRequest_BitPay20.Raw constructor")
                self.status_code = resp.status_code
                self.headers = resp.headers
                self.text = resp.text
                self.url = resp.url
            else:
                self.status_code = kwargs.get('status_code', 0)
                self.headers = requests.structures.CaseInsensitiveDict(kwargs.get('headers', {}))
                self.text = kwargs.get('text', '')
                self.url = kwargs.get('url', '')
        def json(self):
            return json.loads(self.text)
        def serialize(self):
            d = self.get_dict()
            return self.ser_prefix + zlib.compress(json.dumps(d).encode('utf-8'), level=9)
        @classmethod
        def deserialize(cls, ser):
            if not ser.startswith(cls.ser_prefix):
                raise ValueError('Invalid serialized data')
            data = zlib.decompress(ser[len(cls.ser_prefix):])
            d = json.loads(data.decode('utf-8'))
            if not all(s in d for s in cls.__slots__):
                raise ValueError('Missing required keys in deserialized data')
            return cls(**d)
        def get_dict(self):
            d = {}
            for s in self.__slots__:
                val = getattr(self, s, '')
                if isinstance(val, requests.structures.CaseInsensitiveDict):
                    val = dict(val)
                d[s] = val
            return d
        def __str__(self):
            return json.dumps(self.get_dict())
    # /class Raw

    def serialize(self):
        if self.raw:
            return self.raw.serialize()

    @classmethod
    def deserialize(cls, ser):
        return cls(cls.Raw.deserialize(ser))

    def export_file_data(self):
        ''' Returns bytes suitable to be saved to a file '''
        return json.dumps(self.raw.get_dict(), indent=4).encode('utf-8')

    @classmethod
    def export_file_ext(cls):
        return 'json'

    def parse(self, r):
        ''' Overrides super. r is a self.Raw object. '''
        if self.error:
            return
        if not isinstance(r, self.Raw):  # BitPay2.0 requires 'raw' be a Raw instance
            self.error = 'Argument not of the proper type (expected PaymentRequest_BitPay20.Raw instance)'
            return
        self.data, self.id, self.details, self.outputs, self.memo, self.payment_url, self.headers = (None,)*7  # ensure attributes defined
        try:
            if r.status_code == 400:
                # error 400, has special info in r.text
                raise ResponseError(r.text)
            assert r.status_code == 200, f"Bad response status: {r.status_code}"
            self.headers = r.headers.copy()
            self.data = j = r.json()
            self.id = j['paymentId']
            self.details = self.Details(
                outputs = j['outputs'],
                memo = j['memo'],
                payment_url = j['paymentUrl'],
                time = dateutil.parser.parse(j['time']).timestamp(),
                expires = dateutil.parser.parse(j['expires']).timestamp(),
                network = j.get('network', 'main'),
                currency = j.get('currency', 'BCH'),
                required_fee_rate = j.get('requiredFeeRate', 1),
            )
            self.outputs = []
            for o in self.details.outputs:
                amt, addr = o['amount'], Address.from_string(o['address'])
                self.outputs.append((TYPE_ADDRESS, addr, amt))
            self.memo = self.details.memo
            self.payment_url = self.details.payment_url
        except ResponseError as e:
            self.error = str(e)
        except (KeyError, ValueError, TypeError, AssertionError, IndexError) as e:
            self.error = f'cannot parse payment request ({str(e)})'
        except Exception as e:
            self.print_error("Error parsing payment prequest", repr(e))
            self.error = 'Low-level error encountered parsing the payment request'


    # super methods that work ok for us:
    #   def is_pr(self) -> bool
    #   def get_outputs(self) -> list
    #   def get_id(self) -> str
    #   def get_dict(self) -> dict
    #   def get_memo(self) -> str
    #   def get_verify_status(self) -> str
    #   def get_requestor(self) -> Address?
    #   def get_amount(self) -> int
    #   def get_address(self) -> Address
    #   def get_expiration_date(self) -> float
    #   def get_payment_url(self) -> str
    #   def has_expired(self) -> bool

    def base_url(self):
        r = self.raw
        url = getattr(r, 'url', None)
        if url:
            up = urllib.parse.urlparse(url)
            return f'{up.scheme}://{up.netloc}'
        return ''

    # Cache the signing keys
    _signing_keys = [ 0.0, 'BitPay, Inc.', set() ]
    _signing_keys_lock = threading.Lock()
    _pgp_key_data = {}

    def _get_signing_keys(self, timeout=10.0):
        return self._signing_keys

        # NOTE: the below is turned-off for now
        # We need to hear from BitPay on how best to handle this.
        # It appears to be much ado about nothing since the PGP keys
        # come from the web *anyway*.  What's more -- we need to depend
        # on Python PGP libs now, which is a rather heavy dependency. :/

        if not self._pgp_key_data:
            try:
                pgp_key_data = requests.get('https://bitpay.com/pgp-keys.json', timeout=timeout, verify=True).json()['pgpKeys']
                pgp_key_data = { d['fingerprint'] : { 'owner' : d['owner'], 'publicKey' : d['publicKey'] } for d in pgp_key_data }
                with self._signing_keys_lock:
                    self._pgp_key_data.update(pgp_key_data)
            except Exception as e:
                self.print_error('Failed to get PGP keys:', repr(e))
        # TODO FIXME XXX: Use the PGP keys above to verify the retrieved keys below
        # The problem is as follows: PGP dependencies in python, which are a bit
        # heavy-handed. The URL for requesting sigs for the below would be:
        #
        # https://test.bitpay.com/signatures/<paymentProtocol.json_RESPONSE_SHA256_HASH>.json
        #
        # See: https://bitpay.com/docs/payment-protocol
        ts, owner, signing_pubkeys = self._signing_keys
        if not signing_pubkeys or abs(time.time()-ts) > 60.0*60.0:  # we keep the cached keys for up to 1 hour
            url = self.base_url() + '/signingKeys/paymentProtocol.json'
            try:
                r2 = requests.get(url, timeout=timeout, verify=True)
                if r2.status_code != 200:
                    raise RuntimeError(f'Bad status when retrieving signing keys: {r2.status_code}')
                with self._signing_keys_lock:
                    signing_pubkeys.clear()
                    d = r2.json()
                    exp = dateutil.parser.parse(d['expirationDate']).timestamp()
                    if exp < time.time():
                        self.print_error("Warning: BitPay returned expired keys expirationDate=", d['expirationDate'])
                    owner = d.get('owner', owner)
                    for k in d['publicKeys']:
                        pk = PublicKey.from_string(k)
                        signing_pubkeys.add(pk)
            except requests.RequestException as e:
                self.error = 'error retrieving keys: ' + repr(e)
                self.print_error(self.error)
                raise
            except Exception as e:
                self.error = 'error parsing signing keys: ' + repr(e)
                self.print_error(self.error)
                raise
            self._signing_keys[0] = time.time()
            self._signing_keys[1] = owner
        return self._signing_keys

    def verify(self, contacts, *, timeout=10.0):
        self.print_error("Verify")
        # NB: contacts is ignored
        if self.error:
            return False
        if not self.raw:
            self.error = "Empty request"
            return False
        r = self.raw
        try:
            if r.status_code != 200:
                if r.status_code == 400:
                    raise ValueError(r.text)
                raise ValueError(f'Bad HTTP respone code: {r.status_code}')
            sig = bytes.fromhex(r.headers['signature'])
            digest = r.headers['digest']
            if not digest.upper().startswith('SHA-256='):
                raise ValueError('Unknown digest')
            digest = bytes.fromhex(digest.split('=', 1)[1])
            if len(digest) != 32:
                raise ValueError('Bad digest')
            addr = Address.from_string(r.headers['x-identity'])
            if bitcoin.sha256(r.text) != digest:
                raise ValueError('Digest does not match payload')
            msg = digest
        except Exception as e:
            self.error = 'error processing response:' + repr(e)
            self.print_error(self.error)
            return False

        # Grab Signing keys either from cache or from BitPay
        try:
            ts, owner, signing_pubkeys = self._get_signing_keys(timeout=timeout)
        except Exception as e:
            # Error retrieving signing pubkeys, try using cached values
            # if that fails.. just abort.
            ts, owner, signing_pubkeys = self._signing_keys
            if not signing_pubkeys:
                return False
            self.error = None  # clear error

        # they don't include the nV byte so we have to try a bunch of stuff here
        for nV in (27, 28, 31, 32):
            pk, comp = bitcoin.pubkey_from_signature(bytes([nV]) + sig, msg)
            pubkey = bitcoin.point_to_ser(pk.pubkey.point, comp)
            sig_addr = Address.from_pubkey(pubkey)
            if addr == sig_addr:
                self.print_error("Signing address found and matches")
                if PublicKey.from_pubkey(pubkey) in signing_pubkeys:
                    self.print_error('Signing pubkey is valid')
                else:
                    # TODO: Fixme -- for now this branch will always be taken because we turned off key download in _get_signing_keys() above
                    self.print_error('Warning: Could not verify whether signing public key is valid:', pubkey.hex(), "(PGP verification is currently disabled)")
                self.requestor = sig_addr.to_ui_string()
                break
        else:
            self.error = 'failed to verify signature against retrieved keys'
            self.print_error(self.error)
            return False

        ### SIG Verified
        self.error = 'Signed by: ' + owner  # <--- This is not ideal because we re-use self.error for a *non-error* but the superclass API is this way. -Calin
        return True

    def verify_x509(self, paymntreq):
        raise NotImplementedError()

    def verify_dnssec(self, pr, contacts):
        raise NotImplementedError()

    def send_payment(self, raw_tx, refund_addr, *, timeout=10.0):
        self.print_error("Send payment")
        # NB: refund_addr is ignored
        self.tx = None
        # First, verify that BitPay would accept the payment by sending
        # a verify-payment message via HTTP
        tx = Transaction(raw_tx)
        #def from_io(klass, inputs, outputs, locktime=0, sign_schnorr=False):
        unsigned_tx = Transaction.from_io(tx.inputs(), tx.outputs(), locktime=tx.locktime, sign_schnorr=tx.is_schnorr_signed(0))
        h = self.HEADERS.copy()
        h['Content-Type'] = 'application/verify-payment'
        unsigned_raw = unsigned_tx.serialize(True)
        body = {
            'currency' : self.details.currency or 'BCH',
            'unsignedTransaction' : unsigned_raw,
            'weightedSize' : len(unsigned_raw)//2
        }
        try:
            r = requests.post(self.raw.url, headers=h, data=json.dumps(body).encode('utf-8'))
        except requests.RequestException as e:
            return False, str(e)
        if r.status_code != 200:
            # Propagate 'Bad request' (HTTP 400) messages to the user since they
            # contain valuable information.
            if r.status_code == 400:
                return False, (r.reason + ": " + r.content.decode('UTF-8'))
            # Some other errors might display an entire HTML document.
            # Hide those and just display the name of the error code.
            return False, r.reason
        memo = r.json().get('memo', '?').lower()
        if 'valid' not in memo:
            return False, f"Did not receive 'valid': {memo}"

        # Ok, all is valid -- now actually send the tx
        h['Content-Type'] = 'application/payment'
        body = {
            'currency' : self.details.currency or 'BCH',
            'transactions' : [ raw_tx ]
        }
        try:
            r = requests.post(self.raw.url, headers=h, data=json.dumps(body).encode('utf-8'))
        except requests.RequestException as e:
            return False, str(e)
        if r.status_code != 200:
            # Propagate 'Bad request' (HTTP 400) messages to the user since they
            # contain valuable information.
            if r.status_code == 400:
                return False, (r.reason + ": " + r.content.decode('UTF-8'))
            # Some other errors might display an entire HTML document.
            # Hide those and just display the name of the error code.
            return False, r.reason
        memo = r.json().get('memo', '?')

        self.tx = Transaction._txid(raw_tx)  # save txid

        return True, memo


def get_payment_request_bitpay20(url, timeout=10.0):
    ''' Synchronously contacts BitPay and gets the payment request.
    Returns the PaymentRequest object. Returned PaymentRequest
    has .error != None on error. '''
    headers = PaymentRequest_BitPay20.HEADERS.copy()
    headers.update({'accept' : 'application/payment-request'})
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=True)
        if r.status_code == 400:
            raise ResponseError(r.text)
        r.raise_for_status()
        return PaymentRequest_BitPay20(PaymentRequest_BitPay20.Raw(response=r))
    except Exception as e:
        print_error('[BitPay2.0] get_payment_request:', repr(e))
        return PaymentRequest(None, error=str(e))
