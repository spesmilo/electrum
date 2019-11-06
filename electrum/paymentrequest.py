#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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
from typing import Optional

import certifi
import urllib.parse
import aiohttp


try:
    from . import paymentrequest_pb2 as pb2
except ImportError:
    sys.exit("Error: could not find paymentrequest_pb2.py. Create it with 'protoc --proto_path=electrum/ --python_out=electrum/ electrum/paymentrequest.proto'")

from . import bitcoin, ecc, util, transaction, x509, rsakey
from .util import bh2u, bfh, export_meta, import_meta, make_aiohttp_session
from .crypto import sha256
from .bitcoin import TYPE_ADDRESS
from .transaction import TxOutput
from .network import Network
from .logging import get_logger, Logger


_logger = get_logger(__name__)


REQUEST_HEADERS = {'Accept': 'application/bitcoin-paymentrequest', 'User-Agent': 'Electrum'}
ACK_HEADERS = {'Content-Type':'application/bitcoin-payment','Accept':'application/bitcoin-paymentack','User-Agent':'Electrum'}

ca_path = certifi.where()
ca_list = None
ca_keyID = None

def load_ca_list():
    global ca_list, ca_keyID
    if ca_list is None:
        ca_list, ca_keyID = x509.load_certificates(ca_path)



# status of payment requests
PR_UNPAID  = 0
PR_EXPIRED = 1
PR_UNKNOWN = 2     # sent but not propagated
PR_PAID    = 3     # send and propagated


async def get_payment_request(url: str) -> 'PaymentRequest':
    u = urllib.parse.urlparse(url)
    error = None
    if u.scheme in ('http', 'https'):
        resp_content = None
        try:
            proxy = Network.get_instance().proxy
            async with make_aiohttp_session(proxy, headers=REQUEST_HEADERS) as session:
                async with session.get(url) as response:
                    resp_content = await response.read()
                    response.raise_for_status()
                    # Guard against `bitcoin:`-URIs with invalid payment request URLs
                    if "Content-Type" not in response.headers \
                    or response.headers["Content-Type"] != "application/bitcoin-paymentrequest":
                        data = None
                        error = "payment URL not pointing to a payment request handling server"
                    else:
                        data = resp_content
                    data_len = len(data) if data is not None else None
                    _logger.info(f'fetched payment request {url} {data_len}')
        except aiohttp.ClientError as e:
            error = f"Error while contacting payment URL: {url}.\nerror type: {type(e)}"
            if isinstance(e, aiohttp.ClientResponseError):
                error += f"\nGot HTTP status code {e.status}."
                if resp_content:
                    try:
                        error_text_received = resp_content.decode("utf8")
                    except UnicodeDecodeError:
                        error_text_received = "(failed to decode error)"
                    else:
                        error_text_received = error_text_received[:400]
                    error_oneline = ' -- '.join(error.split('\n'))
                    _logger.info(f"{error_oneline} -- [DO NOT TRUST THIS MESSAGE] "
                                 f"{repr(e)} text: {error_text_received}")
            data = None
    elif u.scheme == 'file':
        try:
            with open(u.path, 'r', encoding='utf-8') as f:
                data = f.read()
        except IOError:
            data = None
            error = "payment URL not pointing to a valid file"
    else:
        data = None
        error = f"Unknown scheme for payment request. URL: {url}"
    pr = PaymentRequest(data, error=error)
    return pr


class PaymentRequest:

    def __init__(self, data, *, error=None):
        self.raw = data
        self.error = error  # FIXME overloaded and also used when 'verify' succeeds
        self.parse(data)
        self.requestor = None # known after verify
        self.tx = None

    def __str__(self):
        return str(self.raw)

    def parse(self, r):
        self.outputs = []
        if self.error:
            return
        self.id = bh2u(sha256(r)[0:16])
        try:
            self.data = pb2.PaymentRequest()
            self.data.ParseFromString(r)
        except:
            self.error = "cannot parse payment request"
            return
        self.details = pb2.PaymentDetails()
        self.details.ParseFromString(self.data.serialized_payment_details)
        for o in self.details.outputs:
            type_, addr = transaction.get_address_from_output_script(o.script)
            if type_ != TYPE_ADDRESS:
                # TODO maybe rm restriction but then get_requestor and get_id need changes
                self.error = "only addresses are allowed as outputs"
                return
            self.outputs.append(TxOutput(type_, addr, o.amount))
        self.memo = self.details.memo
        self.payment_url = self.details.payment_url

    def is_pr(self):
        return self.get_amount() != 0
        #return self.get_outputs() != [(TYPE_ADDRESS, self.get_requestor(), self.get_amount())]

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
            # the address will be displayed as requestor
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
            _logger.exception('')
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
        else:
            self.error = f"ERROR: unknown pki_type {paymntreq.pki_type} in Payment Request"
            return False
        if not verify:
            self.error = "ERROR: Invalid Signature for Payment Request Data"
            return False
        ### SIG Verified
        self.error = 'Signed by Trusted CA: ' + ca.get_common_name()
        return True

    def verify_dnssec(self, pr, contacts):
        sig = pr.signature
        alias = pr.pki_data
        info = contacts.resolve(alias)
        if info.get('validated') is not True:
            self.error = "Alias verification failed (DNSSEC)"
            return False
        if pr.pki_type == "dnssec+btc":
            self.requestor = alias
            address = info.get('address')
            pr.signature = b''
            message = pr.SerializeToString()
            if ecc.verify_message_with_address(address, sig, message):
                self.error = 'Verified with DNSSEC'
                return True
            else:
                self.error = "verify failed"
                return False
        else:
            self.error = "unknown algo"
            return False

    def has_expired(self) -> Optional[bool]:
        if not hasattr(self, 'details'):
            return None
        return self.details.expires and self.details.expires < int(time.time())

    def get_expiration_date(self):
        return self.details.expires

    def get_amount(self):
        return sum(map(lambda x:x[2], self.outputs))

    def get_address(self):
        o = self.outputs[0]
        assert o.type == TYPE_ADDRESS
        return o.address

    def get_requestor(self):
        return self.requestor if self.requestor else self.get_address()

    def get_verify_status(self):
        return self.error if self.requestor else "No Signature"

    def get_memo(self):
        return self.memo

    def get_dict(self):
        return {
            'requestor': self.get_requestor(),
            'memo':self.get_memo(),
            'exp': self.get_expiration_date(),
            'amount': self.get_amount(),
            'signature': self.get_verify_status(),
            'txid': self.tx,
            'outputs': self.get_outputs()
        }

    def get_id(self):
        return self.id if self.requestor else self.get_address()

    def get_outputs(self):
        return self.outputs[:]

    async def send_payment_and_receive_paymentack(self, raw_tx, refund_addr):
        pay_det = self.details
        if not self.details.payment_url:
            return False, "no url"
        paymnt = pb2.Payment()
        paymnt.merchant_data = pay_det.merchant_data
        paymnt.transactions.append(bfh(raw_tx))
        ref_out = paymnt.refund_to.add()
        ref_out.script = util.bfh(transaction.Transaction.pay_script(TYPE_ADDRESS, refund_addr))
        paymnt.memo = "Paid using Electrum"
        pm = paymnt.SerializeToString()
        payurl = urllib.parse.urlparse(pay_det.payment_url)
        resp_content = None
        try:
            proxy = Network.get_instance().proxy
            async with make_aiohttp_session(proxy, headers=ACK_HEADERS) as session:
                async with session.post(payurl.geturl(), data=pm) as response:
                    resp_content = await response.read()
                    response.raise_for_status()
                    try:
                        paymntack = pb2.PaymentACK()
                        paymntack.ParseFromString(resp_content)
                    except Exception:
                        return False, "PaymentACK could not be processed. Payment was sent; please manually verify that payment was received."
                    print(f"PaymentACK message received: {paymntack.memo}")
                    return True, paymntack.memo
        except aiohttp.ClientError as e:
            error = f"Payment Message/PaymentACK Failed:\nerror type: {type(e)}"
            if isinstance(e, aiohttp.ClientResponseError):
                error += f"\nGot HTTP status code {e.status}."
                if resp_content:
                    try:
                        error_text_received = resp_content.decode("utf8")
                    except UnicodeDecodeError:
                        error_text_received = "(failed to decode error)"
                    else:
                        error_text_received = error_text_received[:400]
                    error_oneline = ' -- '.join(error.split('\n'))
                    _logger.info(f"{error_oneline} -- [DO NOT TRUST THIS MESSAGE] "
                                 f"{repr(e)} text: {error_text_received}")
            return False, error


def make_unsigned_request(req):
    from .transaction import Transaction
    addr = req['address']
    time = req.get('time', 0)
    exp = req.get('exp', 0)
    if time and type(time) != int:
        time = 0
    if exp and type(exp) != int:
        exp = 0
    amount = req['amount']
    if amount is None:
        amount = 0
    memo = req['memo']
    script = bfh(Transaction.pay_script(TYPE_ADDRESS, addr))
    outputs = [(script, amount)]
    pd = pb2.PaymentDetails()
    for script, amount in outputs:
        pd.outputs.add(amount=amount, script=script)
    pd.time = time
    pd.expires = time + exp if exp else 0
    pd.memo = memo
    pr = pb2.PaymentRequest()
    pr.serialized_payment_details = pd.SerializeToString()
    pr.signature = util.to_bytes('')
    return pr


def sign_request_with_alias(pr, alias, alias_privkey):
    pr.pki_type = 'dnssec+btc'
    pr.pki_data = str(alias)
    message = pr.SerializeToString()
    ec_key = ecc.ECPrivkey(alias_privkey)
    compressed = bitcoin.is_compressed_privkey(alias_privkey)
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
                raise Exception("ERROR: Supplied CA Certificate Error")
    if not cert_num > 1:
        raise Exception("ERROR: CA Certificate Chain Not Provided by Payment Processor")
    # if the root CA is not supplied, add it to the chain
    ca = x509_chain[cert_num-1]
    if ca.getFingerprint() not in ca_list:
        keyID = ca.get_issuer_keyID()
        f = ca_keyID.get(keyID)
        if f:
            root = ca_list[f]
            x509_chain.append(root)
        else:
            raise Exception("Supplied CA Not Found in Trusted CA Store.")
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
            raise Exception("Algorithm not supported: {}".format(algo))
        if not verify:
            raise Exception("Certificate not Signed by Provided CA Certificate Chain")

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
    pr.pki_data = certificates.SerializeToString()
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
        pr.pki_data = str(requestor)
    return pr


def make_request(config, req):
    pr = make_unsigned_request(req)
    key_path = config.get('ssl_privkey')
    cert_path = config.get('ssl_chain')
    if key_path and cert_path:
        sign_request_with_x509(pr, key_path, cert_path)
    return pr



class InvoiceStore(Logger):

    def __init__(self, storage):
        Logger.__init__(self)
        self.storage = storage
        self.invoices = {}
        self.paid = {}
        d = self.storage.get('invoices', {})
        self.load(d)

    def set_paid(self, pr, txid):
        pr.tx = txid
        pr_id = pr.get_id()
        self.paid[txid] = pr_id
        if pr_id not in self.invoices:
            # in case the user had deleted it previously
            self.add(pr)

    def load(self, d):
        for k, v in d.items():
            try:
                pr = PaymentRequest(bfh(v.get('hex')))
                pr.tx = v.get('txid')
                pr.requestor = v.get('requestor')
                self.invoices[k] = pr
                if pr.tx:
                    self.paid[pr.tx] = k
            except:
                continue

    def import_file(self, path):
        def validate(data):
            return data  # TODO
        import_meta(path, validate, self.on_import)

    def on_import(self, data):
        self.load(data)
        self.save()

    def export_file(self, filename):
        export_meta(self.dump(), filename)

    def dump(self):
        d = {}
        for k, pr in self.invoices.items():
            d[k] = {
                'hex': bh2u(pr.raw),
                'requestor': pr.requestor,
                'txid': pr.tx
            }
        return d

    def save(self):
        self.storage.put('invoices', self.dump())

    def get_status(self, key):
        pr = self.get(key)
        if pr is None:
            self.logger.info(f"get_status() can't find pr for {key}")
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
        self.invoices.pop(key)
        self.save()

    def get(self, k):
        return self.invoices.get(k)

    def sorted_list(self):
        # sort
        return self.invoices.values()

    def unpaid_invoices(self):
        return [self.invoices[k] for k in
                filter(lambda x: self.get_status(x) not in (PR_PAID, None),
                       self.invoices.keys())
                ]
