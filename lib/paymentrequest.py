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
import os.path
import re
import sys
import threading
import time
import traceback
import urlparse
import json
import requests

try:
    import paymentrequest_pb2 as pb2
except ImportError:
    sys.exit("Error: could not find paymentrequest_pb2.py. Create it with 'protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto'")

import bitcoin
import util
from util import print_error
import transaction
import x509
import rsakey

from bitcoin import TYPE_ADDRESS

REQUEST_HEADERS = {'Accept': 'application/bitcoin-paymentrequest', 'User-Agent': 'Electrum'}
ACK_HEADERS = {'Content-Type':'application/bitcoin-payment','Accept':'application/bitcoin-paymentack','User-Agent':'Electrum'}

ca_path = requests.certs.where()
ca_list, ca_keyID = x509.load_certificates(ca_path)


# status of payment requests
PR_UNPAID  = 0
PR_EXPIRED = 1
PR_UNKNOWN = 2     # sent but not propagated
PR_PAID    = 3     # send and propagated



def get_payment_request(url):
    u = urlparse.urlparse(url)
    if u.scheme in ['http', 'https']:
        response = requests.request('GET', url, headers=REQUEST_HEADERS)
        data = response.content
        print_error('fetched payment request', url, len(data))
    elif u.scheme == 'file':
        with open(u.path, 'r') as f:
            data = f.read()
    else:
        raise BaseException("unknown scheme", url)
    pr = PaymentRequest(data)
    return pr


class PaymentRequest:

    def __init__(self, data):
        self.raw = data
        self.parse(data)
        self.requestor = None # known after verify
        self.tx = None
        self.error = None

    def __str__(self):
        return self.raw

    def parse(self, r):
        self.id = bitcoin.sha256(r)[0:16].encode('hex')
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
        #return self.get_outputs() != [(TYPE_ADDRESS, self.get_requestor(), self.get_amount())]

    def verify(self, contacts):
        if not self.raw:
            self.error = "Empty request"
            return
        pr = pb2.PaymentRequest()
        try:
            pr.ParseFromString(self.raw)
        except:
            self.error = "Error: Cannot parse payment request"
            return
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
        paymntreq.signature = ''
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
        alias = pr.pki_data
        info = contacts.resolve(alias)
        if info.get('validated') is not True:
            self.error = "Alias verification failed (DNSSEC)"
            return False
        if pr.pki_type == "dnssec+btc":
            self.requestor = alias
            address = info.get('address')
            pr.signature = ''
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
        return o[1]

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

    def send_ack(self, raw_tx, refund_addr):

        pay_det = self.details
        if not self.details.payment_url:
            return False, "no url"

        paymnt = pb2.Payment()
        paymnt.merchant_data = pay_det.merchant_data
        paymnt.transactions.append(raw_tx)

        ref_out = paymnt.refund_to.add()
        ref_out.script = transaction.Transaction.pay_script(TYPE_ADDRESS, refund_addr)
        paymnt.memo = "Paid using Electrum"
        pm = paymnt.SerializeToString()

        payurl = urlparse.urlparse(pay_det.payment_url)
        try:
            r = requests.post(payurl.geturl(), data=pm, headers=ACK_HEADERS, verify=ca_path)
        except requests.exceptions.SSLError:
            print "Payment Message/PaymentACK verify Failed"
            try:
                r = requests.post(payurl.geturl(), data=pm, headers=ACK_HEADERS, verify=False)
            except Exception as e:
                print e
                return False, "Payment Message/PaymentACK Failed"

        if r.status_code >= 500:
            return False, r.reason

        try:
            paymntack = pb2.PaymentACK()
            paymntack.ParseFromString(r.content)
        except Exception:
            return False, "PaymentACK could not be processed. Payment was sent; please manually verify that payment was received."

        print "PaymentACK message received: %s" % paymntack.memo
        return True, paymntack.memo

    def set_paid(self, tx_hash):
        self.tx = tx_hash


def make_unsigned_request(req):
    from transaction import Transaction
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
    script = Transaction.pay_script(TYPE_ADDRESS, addr).decode('hex')
    outputs = [(script, amount)]
    pd = pb2.PaymentDetails()
    for script, amount in outputs:
        pd.outputs.add(amount=amount, script=script)
    pd.time = time
    pd.expires = time + exp if exp else 0
    pd.memo = memo
    pr = pb2.PaymentRequest()
    pr.serialized_payment_details = pd.SerializeToString()
    pr.signature = ''
    return pr


def sign_request_with_alias(pr, alias, alias_privkey):
    pr.pki_type = 'dnssec+btc'
    pr.pki_data = str(alias)
    message = pr.SerializeToString()
    ec_key = bitcoin.regenerate_key(alias_privkey)
    address = bitcoin.address_from_private_key(alias_privkey)
    compressed = bitcoin.is_compressed(alias_privkey)
    pr.signature = ec_key.sign_message(message, compressed, address)



def verify_cert_chain(chain):
    """ Verify a chain of certificates. The last certificate is the CA"""
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
    import pem
    key_path = config.get('ssl_privkey')
    cert_path = config.get('ssl_chain')
    with open(key_path, 'r') as f:
        params = pem.parse_private_key(f.read())
    with open(cert_path, 'r') as f:
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
    import pem
    with open(key_path, 'r') as f:
        params = pem.parse_private_key(f.read())
        privkey = rsakey.RSAKey(*params)
    with open(cert_path, 'r') as f:
        s = f.read()
        bList = pem.dePemList(s, "CERTIFICATE")
    certificates = pb2.X509Certificates()
    certificates.certificate.extend(map(str, bList))
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
        pr.signature = signature.decode('hex')
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



class InvoiceStore(object):

    def __init__(self, config):
        self.config = config
        self.invoices = {}
        self.load_invoices()

    def load_invoices(self):
        path = os.path.join(self.config.path, 'invoices')
        try:
            with open(path, 'r') as f:
                d = json.loads(f.read())
        except:
            return
        for k, v in d.items():
            try:
                pr = PaymentRequest(v.get('hex').decode('hex'))
                pr.tx = v.get('txid')
                pr.requestor = v.get('requestor')
                self.invoices[k] = pr
            except:
                continue

    def save(self):
        l = {}
        for k, pr in self.invoices.items():
            l[k] = {
                'hex': str(pr).encode('hex'),
                'requestor': pr.requestor,
                'txid': pr.tx
            }
        path = os.path.join(self.config.path, 'invoices')
        with open(path, 'w') as f:
            s = json.dumps(l, indent=4, sort_keys=True)
            r = f.write(s)

    def get_status(self, key):
        pr = self.get(key)
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

