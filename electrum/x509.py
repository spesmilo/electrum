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
import time
from datetime import datetime

from . import util
from .util import profiler, bh2u
from .logging import get_logger


_logger = get_logger(__name__)


# algo OIDs
ALGO_RSA_SHA1 = '1.2.840.113549.1.1.5'
ALGO_RSA_SHA256 = '1.2.840.113549.1.1.11'
ALGO_RSA_SHA384 = '1.2.840.113549.1.1.12'
ALGO_RSA_SHA512 = '1.2.840.113549.1.1.13'
ALGO_ECDSA_SHA256 = '1.2.840.10045.4.3.2'

# prefixes, see http://stackoverflow.com/questions/3713774/c-sharp-how-to-calculate-asn-1-der-encoding-of-a-particular-hash-algorithm
PREFIX_RSA_SHA256 = bytearray(
    [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20])
PREFIX_RSA_SHA384 = bytearray(
    [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30])
PREFIX_RSA_SHA512 = bytearray(
    [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40])

# types used in ASN1 structured data
ASN1_TYPES = {
    'BOOLEAN'          : 0x01,
    'INTEGER'          : 0x02,
    'BIT STRING'       : 0x03,
    'OCTET STRING'     : 0x04,
    'NULL'             : 0x05,
    'OBJECT IDENTIFIER': 0x06,
    'SEQUENCE'         : 0x70,
    'SET'              : 0x71,
    'PrintableString'  : 0x13,
    'IA5String'        : 0x16,
    'UTCTime'          : 0x17,
    'GeneralizedTime'  : 0x18,
    'ENUMERATED'       : 0x0A,
    'UTF8String'       : 0x0C,
}


class CertificateError(Exception):
    pass


# helper functions
def bitstr_to_bytestr(s):
    if s[0] != 0x00:
        raise TypeError('no padding')
    return s[1:]


def bytestr_to_int(s):
    i = 0
    for char in s:
        i <<= 8
        i |= char
    return i


def decode_OID(s):
    r = []
    r.append(s[0] // 40)
    r.append(s[0] % 40)
    k = 0
    for i in s[1:]:
        if i < 128:
            r.append(i + 128 * k)
            k = 0
        else:
            k = (i - 128) + 128 * k
    return '.'.join(map(str, r))


def encode_OID(oid):
    x = [int(i) for i in oid.split('.')]
    s = chr(x[0] * 40 + x[1])
    for i in x[2:]:
        ss = chr(i % 128)
        while i > 128:
            i //= 128
            ss = chr(128 + i % 128) + ss
        s += ss
    return s


class ASN1_Node(bytes):
    def get_node(self, ix):
        # return index of first byte, first content byte and last byte.
        first = self[ix + 1]
        if (first & 0x80) == 0:
            length = first
            ixf = ix + 2
            ixl = ixf + length - 1
        else:
            lengthbytes = first & 0x7F
            length = bytestr_to_int(self[ix + 2:ix + 2 + lengthbytes])
            ixf = ix + 2 + lengthbytes
            ixl = ixf + length - 1
        return ix, ixf, ixl

    def root(self):
        return self.get_node(0)

    def next_node(self, node):
        ixs, ixf, ixl = node
        return self.get_node(ixl + 1)

    def first_child(self, node):
        ixs, ixf, ixl = node
        if self[ixs] & 0x20 != 0x20:
            raise TypeError('Can only open constructed types.', hex(self[ixs]))
        return self.get_node(ixf)

    def is_child_of(node1, node2):
        ixs, ixf, ixl = node1
        jxs, jxf, jxl = node2
        return ((ixf <= jxs) and (jxl <= ixl)) or ((jxf <= ixs) and (ixl <= jxl))

    def get_all(self, node):
        # return type + length + value
        ixs, ixf, ixl = node
        return self[ixs:ixl + 1]

    def get_value_of_type(self, node, asn1_type):
        # verify type byte and return content
        ixs, ixf, ixl = node
        if ASN1_TYPES[asn1_type] != self[ixs]:
            raise TypeError('Wrong type:', hex(self[ixs]), hex(ASN1_TYPES[asn1_type]))
        return self[ixf:ixl + 1]

    def get_value(self, node):
        ixs, ixf, ixl = node
        return self[ixf:ixl + 1]

    def get_children(self, node):
        nodes = []
        ii = self.first_child(node)
        nodes.append(ii)
        while ii[2] < node[2]:
            ii = self.next_node(ii)
            nodes.append(ii)
        return nodes

    def get_sequence(self):
        return list(map(lambda j: self.get_value(j), self.get_children(self.root())))

    def get_dict(self, node):
        p = {}
        for ii in self.get_children(node):
            for iii in self.get_children(ii):
                iiii = self.first_child(iii)
                oid = decode_OID(self.get_value_of_type(iiii, 'OBJECT IDENTIFIER'))
                iiii = self.next_node(iiii)
                value = self.get_value(iiii)
                p[oid] = value
        return p

    def decode_time(self, ii):
        GENERALIZED_TIMESTAMP_FMT = '%Y%m%d%H%M%SZ'
        UTCTIME_TIMESTAMP_FMT = '%y%m%d%H%M%SZ'

        try:
            return time.strptime(self.get_value_of_type(ii, 'UTCTime').decode('ascii'), UTCTIME_TIMESTAMP_FMT)
        except TypeError:
            return time.strptime(self.get_value_of_type(ii, 'GeneralizedTime').decode('ascii'), GENERALIZED_TIMESTAMP_FMT)

class X509(object):
    def __init__(self, b):

        self.bytes = bytearray(b)

        der = ASN1_Node(b)
        root = der.root()
        cert = der.first_child(root)
        # data for signature
        self.data = der.get_all(cert)

        # optional version field
        if der.get_value(cert)[0] == 0xa0:
            version = der.first_child(cert)
            serial_number = der.next_node(version)
        else:
            serial_number = der.first_child(cert)
        self.serial_number = bytestr_to_int(der.get_value_of_type(serial_number, 'INTEGER'))

        # signature algorithm
        sig_algo = der.next_node(serial_number)
        ii = der.first_child(sig_algo)
        self.sig_algo = decode_OID(der.get_value_of_type(ii, 'OBJECT IDENTIFIER'))

        # issuer
        issuer = der.next_node(sig_algo)
        self.issuer = der.get_dict(issuer)

        # validity
        validity = der.next_node(issuer)
        ii = der.first_child(validity)
        self.notBefore = der.decode_time(ii)
        ii = der.next_node(ii)
        self.notAfter = der.decode_time(ii)

        # subject
        subject = der.next_node(validity)
        self.subject = der.get_dict(subject)
        subject_pki = der.next_node(subject)
        public_key_algo = der.first_child(subject_pki)
        ii = der.first_child(public_key_algo)
        self.public_key_algo = decode_OID(der.get_value_of_type(ii, 'OBJECT IDENTIFIER'))

        if self.public_key_algo != '1.2.840.10045.2.1':  # for non EC public key
            # pubkey modulus and exponent
            subject_public_key = der.next_node(public_key_algo)
            spk = der.get_value_of_type(subject_public_key, 'BIT STRING')
            spk = ASN1_Node(bitstr_to_bytestr(spk))
            r = spk.root()
            modulus = spk.first_child(r)
            exponent = spk.next_node(modulus)
            rsa_n = spk.get_value_of_type(modulus, 'INTEGER')
            rsa_e = spk.get_value_of_type(exponent, 'INTEGER')
            self.modulus = int.from_bytes(rsa_n, byteorder='big', signed=False)
            self.exponent = int.from_bytes(rsa_e, byteorder='big', signed=False)
        else:
            subject_public_key = der.next_node(public_key_algo)
            spk = der.get_value_of_type(subject_public_key, 'BIT STRING')
            self.ec_public_key = spk

        # extensions
        self.CA = False
        self.AKI = None
        self.SKI = None
        i = subject_pki
        while i[2] < cert[2]:
            i = der.next_node(i)
            d = der.get_dict(i)
            for oid, value in d.items():
                value = ASN1_Node(value)
                if oid == '2.5.29.19':
                    # Basic Constraints
                    self.CA = bool(value)
                elif oid == '2.5.29.14':
                    # Subject Key Identifier
                    r = value.root()
                    value = value.get_value_of_type(r, 'OCTET STRING')
                    self.SKI = bh2u(value)
                elif oid == '2.5.29.35':
                    # Authority Key Identifier
                    self.AKI = bh2u(value.get_sequence()[0])
                else:
                    pass

        # cert signature
        cert_sig_algo = der.next_node(cert)
        ii = der.first_child(cert_sig_algo)
        self.cert_sig_algo = decode_OID(der.get_value_of_type(ii, 'OBJECT IDENTIFIER'))
        cert_sig = der.next_node(cert_sig_algo)
        self.signature = der.get_value(cert_sig)[1:]

    def get_keyID(self):
        # http://security.stackexchange.com/questions/72077/validating-an-ssl-certificate-chain-according-to-rfc-5280-am-i-understanding-th
        return self.SKI if self.SKI else repr(self.subject)

    def get_issuer_keyID(self):
        return self.AKI if self.AKI else repr(self.issuer)

    def get_common_name(self):
        return self.subject.get('2.5.4.3', b'unknown').decode()

    def get_signature(self):
        return self.cert_sig_algo, self.signature, self.data

    def check_ca(self):
        return self.CA

    def check_date(self):
        now = time.gmtime()
        if self.notBefore > now:
            raise CertificateError('Certificate has not entered its valid date range. (%s)' % self.get_common_name())
        if self.notAfter <= now:
            dt = datetime.utcfromtimestamp(time.mktime(self.notAfter))
            raise CertificateError(f'Certificate ({self.get_common_name()}) has expired (at {dt} UTC).')

    def getFingerprint(self):
        return hashlib.sha1(self.bytes).digest()


@profiler
def load_certificates(ca_path):
    from . import pem
    ca_list = {}
    ca_keyID = {}
    # ca_path = '/tmp/tmp.txt'
    with open(ca_path, 'r', encoding='utf-8') as f:
        s = f.read()
    bList = pem.dePemList(s, "CERTIFICATE")
    for b in bList:
        try:
            x = X509(b)
            x.check_date()
        except BaseException as e:
            # with open('/tmp/tmp.txt', 'w') as f:
            #     f.write(pem.pem(b, 'CERTIFICATE').decode('ascii'))
            _logger.info(f"cert error: {e}")
            continue

        fp = x.getFingerprint()
        ca_list[fp] = x
        ca_keyID[x.get_keyID()] = fp

    return ca_list, ca_keyID


if __name__ == "__main__":
    import certifi

    ca_path = certifi.where()
    ca_list, ca_keyID = load_certificates(ca_path)
