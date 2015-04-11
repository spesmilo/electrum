#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import hashlib
import httplib
import os.path
import re
import sys
import threading
import time
import traceback
import urllib2
import urlparse
import requests

try:
    import paymentrequest_pb2 as pb2
except ImportError:
    sys.exit("Error: could not find paymentrequest_pb2.py. Create it with 'protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto'")

import bitcoin
import util
import transaction
import x509


REQUEST_HEADERS = {'Accept': 'application/bitcoin-paymentrequest', 'User-Agent': 'Electrum'}
ACK_HEADERS = {'Content-Type':'application/bitcoin-payment','Accept':'application/bitcoin-paymentack','User-Agent':'Electrum'}

ca_path = requests.certs.where()
ca_list = x509.load_certificates(ca_path)


class PaymentRequest:
    def __init__(self, config):
        self.config = config
        self.outputs = []
        self.error = ""
        self.dir_path = os.path.join( self.config.path, 'requests')
        if not os.path.exists(self.dir_path):
            os.mkdir(self.dir_path)

    def read(self, url):
        self.url = url
        u = urlparse.urlparse(url)
        self.domain = u.netloc
        try:
            connection = httplib.HTTPConnection(u.netloc) if u.scheme == 'http' else httplib.HTTPSConnection(u.netloc)
            connection.request("GET",u.geturl(), headers=REQUEST_HEADERS)
            response = connection.getresponse()
        except:
            self.error = "cannot read url"
            return

        try:
            r = response.read()
        except:
            self.error = "cannot read"
            return

        self.id = bitcoin.sha256(r)[0:16].encode('hex')
        filename = os.path.join(self.dir_path, self.id)
        with open(filename,'wb') as f:
            f.write(r)

        return self.parse(r)


    def get_status(self):
        if self.error:
            return self.error
        else:
            return self.status


    def read_file(self, key):
        filename = os.path.join(self.dir_path, key)
        with open(filename,'rb') as f:
            r = f.read()

        assert key == bitcoin.sha256(r)[0:16].encode('hex')
        self.id = key
        self.parse(r)


    def parse(self, r):
        try:
            self.data = pb2.PaymentRequest()
            self.data.ParseFromString(r)
        except:
            self.error = "cannot parse payment request"
            return
        self.details = pb2.PaymentDetails()
        self.details.ParseFromString(self.data.serialized_payment_details)
        for o in self.details.outputs:
            addr = transaction.get_address_from_output_script(o.script)[1]
            self.outputs.append(('address', addr, o.amount))
        self.memo = self.details.memo
        self.payment_url = self.details.payment_url


    def verify(self):
        if not ca_list:
            self.error = "Trusted certificate authorities list not found"
            return False
        paymntreq = self.data
        if not paymntreq.signature:
            self.error = "No signature"
            return
        cert = pb2.X509Certificates()
        cert.ParseFromString(paymntreq.pki_data)
        cert_num = len(cert.certificate)
        x509_chain = []
        for i in range(cert_num):
            x = x509.X509()
            x.parseBinary(bytearray(cert.certificate[i]))
            x.slow_parse()
            x509_chain.append(x)
            if i == 0:
                try:
                    x.check_date()
                    x.check_name(self.domain)
                except Exception as e:
                    self.error = str(e)
                    return
            else:
                if not x.check_ca():
                    self.error = "ERROR: Supplied CA Certificate Error"
                    return
        if not cert_num > 1:
            self.error = "ERROR: CA Certificate Chain Not Provided by Payment Processor"
            return False
        # if the root CA is not supplied, add it to the chain
        ca = x509_chain[cert_num-1]
        supplied_CA_fingerprint = ca.getFingerprint()
        supplied_CA_names = ca.extract_names()
        CA_OU = supplied_CA_names['OU']
        x = ca_list.get(supplied_CA_fingerprint)
        if x:
            x.slow_parse()
            names = x.extract_names()
            assert names['CN'] == supplied_CA_names['CN']
        else:
            issuer = ca.get_issuer()
            for x in ca_list.values():
                try:
                    x.slow_parse()
                    names = x.extract_names()
                except Exception as e:
                    util.print_error("cannot parse cert:", e)
                    continue
                if names.get('CN') == issuer.get('CN'):
                    x509_chain.append(x)
                    break
            else:
                self.error = "Supplied CA Not Found in Trusted CA Store."
                return False
        # verify the chain of signatures
        cert_num = len(cert.certificate)
        for i in range(1, cert_num):
            x = x509_chain[i]
            prev_x = x509_chain[i-1]
            algo, sig, data = prev_x.extract_sig()
            sig = bytearray(sig[5:])
            pubkey = x.publicKey
            if algo.getComponentByName('algorithm') == x509.ALGO_RSA_SHA1:
                verify = pubkey.hashAndVerify(sig, data)
            elif algo.getComponentByName('algorithm') == x509.ALGO_RSA_SHA256:
                hashBytes = bytearray(hashlib.sha256(data).digest())
                verify = pubkey.verify(sig, x509.PREFIX_RSA_SHA256 + hashBytes)
            elif algo.getComponentByName('algorithm') == x509.ALGO_RSA_SHA384:
                hashBytes = bytearray(hashlib.sha384(data).digest())
                verify = pubkey.verify(sig, x509.PREFIX_RSA_SHA384 + hashBytes)
            elif algo.getComponentByName('algorithm') == x509.ALGO_RSA_SHA512:
                hashBytes = bytearray(hashlib.sha512(data).digest())
                verify = pubkey.verify(sig, x509.PREFIX_RSA_SHA512 + hashBytes)
            else:
                self.error = "Algorithm not supported"
                util.print_error(self.error, algo.getComponentByName('algorithm'))
                return False
            if not verify:
                self.error = "Certificate not Signed by Provided CA Certificate Chain"
                return False
        # verify the BIP70 signature
        pubkey0 = x509_chain[0].publicKey
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
        else:
            self.error = "ERROR: Unsupported PKI Type for Message Signature"
            return False
        if not verify:
            self.error = "ERROR: Invalid Signature for Payment Request Data"
            return False
        ### SIG Verified
        self.status = 'Signed by Trusted CA:\n' + CA_OU
        return True

    def has_expired(self):
        return self.details.expires and self.details.expires < int(time.time())

    def get_expiration_date(self):
        return self.details.expires

    def get_amount(self):
        return sum(map(lambda x:x[2], self.outputs))

    def get_domain(self):
        return self.domain

    def get_memo(self):
        return self.memo

    def get_id(self):
        return self.id

    def get_outputs(self):
        return self.outputs[:]

    def send_ack(self, raw_tx, refund_addr):

        pay_det = self.details
        if not self.details.payment_url:
            return False, "no url"

        paymnt = paymentrequest_pb2.Payment()
        paymnt.merchant_data = pay_det.merchant_data
        paymnt.transactions.append(raw_tx)

        ref_out = paymnt.refund_to.add()
        ref_out.script = transaction.Transaction.pay_script('address', refund_addr)
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



def make_payment_request(amount, script, memo, rsakey=None):
    """Generates a http PaymentRequest object"""
    pd = pb2.PaymentDetails()
    pd.outputs.add(amount=amount, script=script)
    now = int(time.time())
    pd.time = now
    pd.expires = now + 15*60
    pd.memo = memo
    #pd.payment_url = 'http://payment_ack.url'
    pr = pb2.PaymentRequest()
    pr.serialized_payment_details = pd.SerializeToString()
    pr.signature = ''
    if rsakey:
        pr.pki_type = 'x509+sha256'
        pr.pki_data = certificates.SerializeToString()
        msgBytes = bytearray(pr.SerializeToString())
        hashBytes = bytearray(hashlib.sha256(msgBytes).digest())
        sig = rsakey.sign(x509.PREFIX_RSA_SHA256 + hashBytes)
        pr.signature = bytes(sig)
    return pr.SerializeToString()



if __name__ == "__main__":

    util.set_verbosity(True)

    try:
        uri = sys.argv[1]
    except:
        print "usage: %s url"%sys.argv[0]
        print "example url: \"bitcoin:17KjQgnXC96jakzJe9yo8zxqerhqNptmhq?amount=0.0018&r=https%3A%2F%2Fbitpay.com%2Fi%2FMXc7qTM5f87EC62SWiS94z\""
        sys.exit(1)

    address, amount, label, message, request_url = util.parse_URI(uri)
    from simple_config import SimpleConfig
    config = SimpleConfig()
    pr = PaymentRequest(config)
    pr.read(request_url)
    if not pr.verify():
        print 'verify failed'
        print pr.error
        sys.exit(1)

    print 'Payment Request Verified Domain: ', pr.domain
    print 'outputs', pr.outputs
    print 'Payment Memo: ', pr.details.memo

    tx = "blah"
    pr.send_ack(tx, refund_addr = "1vXAXUnGitimzinpXrqDWVU4tyAAQ34RA")
