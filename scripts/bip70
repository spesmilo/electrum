#!/usr/bin/env python3
# create a BIP70 payment request signed with a certificate

import tlslite

from electrum_ltc.transaction import Transaction
from electrum_ltc import paymentrequest
from electrum_ltc import paymentrequest_pb2 as pb2

chain_file = 'mychain.pem'
cert_file = 'mycert.pem'
amount = 1000000
address = "LSh322VzYj7CCSwQJXrP49Lvt2zktLjQbz"
memo = "blah"
out_file = "payreq"


with open(chain_file, 'r') as f:
    chain = tlslite.X509CertChain()
    chain.parsePemList(f.read())

certificates = pb2.X509Certificates()
certificates.certificate.extend(map(lambda x: str(x.bytes), chain.x509List))

with open(cert_file, 'r') as f:
    rsakey = tlslite.utils.python_rsakey.Python_RSAKey.parsePEM(f.read())

script = Transaction.pay_script('address', address).decode('hex')

pr_string = paymentrequest.make_payment_request(amount, script, memo, rsakey)

with open(out_file,'wb') as f:
    f.write(pr_string)

print("Payment request was written to file '%s'"%out_file)
