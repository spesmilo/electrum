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


from datetime import datetime
import sys

import tlslite
import util
from util import profiler, print_error

from asn1tinydecoder import asn1_node_root, asn1_get_all, asn1_get_value, \
                        asn1_get_value_of_type, asn1_node_next, asn1_node_first_child, \
                        asn1_read_length, asn1_node_is_child_of, \
                        bytestr_to_int, bitstr_to_bytestr

# workaround https://github.com/trevp/tlslite/issues/15
tlslite.utils.cryptomath.pycryptoLoaded = False


# algo OIDs
ALGO_RSA_SHA1   = '1.2.840.113549.1.1.5'
ALGO_RSA_SHA256 = '1.2.840.113549.1.1.11'
ALGO_RSA_SHA384 = '1.2.840.113549.1.1.12'
ALGO_RSA_SHA512 = '1.2.840.113549.1.1.13'
ALGO_ECDSA_SHA256 = '1.2.840.10045.4.3.2'

# prefixes, see http://stackoverflow.com/questions/3713774/c-sharp-how-to-calculate-asn-1-der-encoding-of-a-particular-hash-algorithm
PREFIX_RSA_SHA256 = bytearray([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20])
PREFIX_RSA_SHA384 = bytearray([0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30])
PREFIX_RSA_SHA512 = bytearray([0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40])


class CertificateError(Exception):
    pass


def decode_OID(s):
    s = map(ord, s)
    r = []
    r.append(s[0] / 40)
    r.append(s[0] % 40)
    k = 0 
    for i in s[1:]:
        if i < 128:
            r.append(i + 128*k)
            k = 0
        else:
            k = (i - 128) + 128*k
    return '.'.join(map(str, r))

def encode_OID(oid):
    x = map(int, oid.split('.'))
    s = chr(x[0]*40 + x[1])
    for i in x[2:]:
        ss = chr(i % 128)
        while i > 128:
            i = i / 128
            ss = chr(128 + i % 128) + ss
        s += ss
    return s

def asn1_get_children(der, i):
    nodes = []
    ii = asn1_node_first_child(der,i)
    nodes.append(ii)
    while ii[2]<i[2]:
        ii = asn1_node_next(der,ii)
        nodes.append(ii)
    return nodes

def asn1_get_sequence(s):
    return map(lambda j: asn1_get_value(s, j), asn1_get_children(s, asn1_node_root(s)))

def asn1_get_dict(der, i):
    p = {}
    for ii in asn1_get_children(der, i):
        for iii in asn1_get_children(der, ii):
            iiii = asn1_node_first_child(der, iii)
            oid = decode_OID(asn1_get_value_of_type(der, iiii, 'OBJECT IDENTIFIER'))
            iiii = asn1_node_next(der, iiii)
            value = asn1_get_value(der, iiii)
            p[oid] = value
    return p


class X509(tlslite.X509):

    def parseBinary(self, b):

        # call tlslite method first
        tlslite.X509.parseBinary(self, b)

        der = str(b)
        root = asn1_node_root(der)
        cert = asn1_node_first_child(der, root)
        # data for signature
        self.data = asn1_get_all(der, cert)

        # optional version field
        if asn1_get_value(der, cert)[0] == chr(0xa0):
            version = asn1_node_first_child(der, cert)
            serial_number = asn1_node_next(der, version)
        else:
            serial_number = asn1_node_first_child(der, cert)
        self.serial_number = bytestr_to_int(asn1_get_value_of_type(der, serial_number, 'INTEGER'))

        # signature algorithm
        sig_algo = asn1_node_next(der, serial_number)
        ii = asn1_node_first_child(der, sig_algo)
        self.sig_algo = decode_OID(asn1_get_value_of_type(der, ii, 'OBJECT IDENTIFIER'))

        # issuer
        issuer = asn1_node_next(der, sig_algo)
        self.issuer = asn1_get_dict(der, issuer)

        # validity
        validity = asn1_node_next(der, issuer)
        ii = asn1_node_first_child(der, validity)
        self.notBefore = asn1_get_value_of_type(der, ii, 'UTCTime')
        ii = asn1_node_next(der,ii)
        self.notAfter = asn1_get_value_of_type(der, ii, 'UTCTime')

        # subject
        subject = asn1_node_next(der, validity)
        self.subject = asn1_get_dict(der, subject)
        subject_pki = asn1_node_next(der, subject)

        # extensions
        self.CA = False
        self.AKI = None
        self.SKI = None
        i = subject_pki
        while i[2] < cert[2]:
            i = asn1_node_next(der, i)
            d = asn1_get_dict(der, i)
            for oid, value in d.items():
                if oid == '2.5.29.19':
                    # Basic Constraints
                    self.CA = bool(value)
                elif oid == '2.5.29.14':
                    # Subject Key Identifier
                    r = asn1_node_root(value)
                    value = asn1_get_value_of_type(value, r, 'OCTET STRING')
                    self.SKI = value.encode('hex')
                elif oid == '2.5.29.35':
                    # Authority Key Identifier
                    self.AKI = asn1_get_sequence(value)[0].encode('hex')
                else:
                    pass

        # cert signature
        cert_sig_algo = asn1_node_next(der, cert)
        ii = asn1_node_first_child(der, cert_sig_algo)
        self.cert_sig_algo = decode_OID(asn1_get_value_of_type(der, ii, 'OBJECT IDENTIFIER'))
        cert_sig = asn1_node_next(der, cert_sig_algo)
        self.signature = asn1_get_value(der, cert_sig)[1:]
        
    def get_keyID(self):
        # http://security.stackexchange.com/questions/72077/validating-an-ssl-certificate-chain-according-to-rfc-5280-am-i-understanding-th
        return self.SKI if self.SKI else repr(self.subject)

    def get_issuer_keyID(self):
        return self.AKI if self.AKI else repr(self.issuer)

    def get_common_name(self):
        return self.subject.get('2.5.4.3', 'unknown')

    def get_signature(self):
        return self.cert_sig_algo, self.signature, self.data

    def check_ca(self):
        return self.CA

    def check_date(self):
        import time
        now = time.time()
        TIMESTAMP_FMT = '%y%m%d%H%M%SZ'
        not_before = time.mktime(time.strptime(self.notBefore, TIMESTAMP_FMT))
        not_after = time.mktime(time.strptime(self.notAfter, TIMESTAMP_FMT))
        if not_before > now:
            raise CertificateError('Certificate has not entered its valid date range.')
        if not_after <= now:
            raise CertificateError('Certificate has expired.')



class X509CertChain(tlslite.X509CertChain):
    pass





@profiler
def load_certificates(ca_path):
    ca_list = {}
    ca_keyID = {}
    with open(ca_path, 'r') as f:
        s = f.read()
    bList = tlslite.utils.pem.dePemList(s, "CERTIFICATE")
    for b in bList:
        x = X509()
        try:
            x.parseBinary(b)
            x.check_date()
        except BaseException as e:
            util.print_error("cert error:", e)
            continue

        fp = x.getFingerprint()
        ca_list[fp] = x
        ca_keyID[x.get_keyID()] = fp

    return ca_list, ca_keyID


def int_to_bytestr(i):
    s = chr(i % 256)
    while i > 256:
        i >>= 8
        s = chr(i % 256) + s
    return s

def create_csr(commonName, challenge, k):
    import ecdsa, hashlib
    from bitcoin import point_to_ser
    private_key = ecdsa.SigningKey.from_string(k, curve = ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    pubkey = point_to_ser(public_key.pubkey.point, False)
    asn1_type_table = {
	'BOOLEAN':           0x01,	'INTEGER':           0x02,
	'BIT STRING':        0x03,	'OCTET STRING':      0x04,
	'NULL':              0x05,	'OBJECT IDENTIFIER': 0x06,
	'SEQUENCE':          0x30,	'SET':               0x31,
	'PrintableString':   0x13,	'IA5String':         0x16,
	'UTCTime':           0x17,	'ENUMERATED':        0x0A,
	'UTF8String':        0x0C,	'PrintableString':   0x13,
    }
    def x(t, s):
        c = asn1_type_table[t] & 0x3f if type(t) == str else t
        l = len(s)
        if l < 128:
            ls = chr(l)
        else:
            n = int_to_bytestr(l)
            ls = chr(len(n) + 128) + n
        return chr(c) + ls + s
    x_int = lambda i: x('INTEGER', int_to_bytestr(i))
    x_seq = lambda *items: x('SEQUENCE', ''.join(items))
    x_bitstring = lambda s: x('BIT STRING', s)
    x_utf8 = lambda s: x('UTF8String', s)
    x_set = lambda *items: x('SET', ''.join(items))
    x_printable = lambda s: x('PrintableString', s)
    x_obj = lambda oid: x('OBJECT IDENTIFIER', encode_OID(oid))
    body = x_seq(
        x_int(0),
        x_seq(
            x_set(x_seq(x_obj('2.5.4.3'), x_utf8(commonName)))
        ),
        x_seq(
            x_seq(
                x_obj('1.2.840.10045.2.1'),
                x_obj('1.3.132.0.10')
            ),
            x_bitstring(chr(0) + pubkey)
        ),
        x(0xa0, x_seq(x_obj('1.2.840.113549.1.9.7'), x_set(x_utf8(challenge)))
        )
    )
    signature = private_key.sign_deterministic(body, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
    assert public_key.verify(signature, body, hashfunc=hashlib.sha256, sigdecode = ecdsa.util.sigdecode_der)
    csr = x_seq(
        body,
        x_seq(x_obj(ALGO_ECDSA_SHA256)),
        x_bitstring(chr(0) + signature)
    )
    return csr



