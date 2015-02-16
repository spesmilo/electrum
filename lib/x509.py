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

import pyasn1
import pyasn1_modules
import tlslite
import util

# workaround https://github.com/trevp/tlslite/issues/15
tlslite.utils.cryptomath.pycryptoLoaded = False


from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import Any, ObjectIdentifier, OctetString
from pyasn1.type.char import BMPString, IA5String, UTF8String
from pyasn1.type.useful import GeneralizedTime
from pyasn1_modules.rfc2459 import (Certificate, DirectoryString,
                                    SubjectAltName, GeneralNames,
                                    GeneralName)
from pyasn1_modules.rfc2459 import id_ce_subjectAltName as SUBJECT_ALT_NAME
from pyasn1_modules.rfc2459 import id_at_commonName as COMMON_NAME
from pyasn1_modules.rfc2459 import id_at_organizationalUnitName as OU_NAME
from pyasn1_modules.rfc2459 import id_ce_basicConstraints, BasicConstraints
XMPP_ADDR = ObjectIdentifier('1.3.6.1.5.5.7.8.5')
SRV_NAME = ObjectIdentifier('1.3.6.1.5.5.7.8.7')

# algo OIDs
ALGO_RSA_SHA1 = ObjectIdentifier('1.2.840.113549.1.1.5')
ALGO_RSA_SHA256 = ObjectIdentifier('1.2.840.113549.1.1.11')
ALGO_RSA_SHA384 = ObjectIdentifier('1.2.840.113549.1.1.12')
ALGO_RSA_SHA512 = ObjectIdentifier('1.2.840.113549.1.1.13')

# prefixes, see http://stackoverflow.com/questions/3713774/c-sharp-how-to-calculate-asn-1-der-encoding-of-a-particular-hash-algorithm
PREFIX_RSA_SHA256 = bytearray([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20])
PREFIX_RSA_SHA384 = bytearray([0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30])
PREFIX_RSA_SHA512 = bytearray([0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40])


class CertificateError(Exception):
    pass

def decode_str(data):
    encoding = 'utf-16-be' if isinstance(data, BMPString) else 'utf-8'
    return bytes(data).decode(encoding)


class X509(tlslite.X509):
    """Child class of tlslite.X509 that uses pyasn1 to parse cert
    information. Note: pyasn1 is a lot slower than tlslite, so we
    should try to do everything in tlslite.
    """

    def slow_parse(self):
        self.cert = decoder.decode(str(self.bytes), asn1Spec=Certificate())[0]
        self.tbs = self.cert.getComponentByName('tbsCertificate')
        self.subject = self.tbs.getComponentByName('subject')
        self.extensions = self.tbs.getComponentByName('extensions') or []

    def extract_names(self):
        results = {'CN': None,
                   'DNS': set(),
                   'SRV': set(),
                   'URI': set(),
                   'XMPPAddr': set(),
                   'OU': None,}

        # Extract the CommonName(s) from the cert.
        for rdnss in self.subject:
            for rdns in rdnss:
                for name in rdns:
                    oid = name.getComponentByName('type')
                    value = name.getComponentByName('value')

                    if oid == COMMON_NAME:
                        value = decoder.decode(value, asn1Spec=DirectoryString())[0]
                        value = decode_str(value.getComponent())
                        results['CN'] = value

                    elif oid == OU_NAME:
                        value = decoder.decode(value, asn1Spec=DirectoryString())[0]
                        value = decode_str(value.getComponent())
                        results['OU'] = value

        # Extract the Subject Alternate Names (DNS, SRV, URI, XMPPAddr)
        for extension in self.extensions:
            oid = extension.getComponentByName('extnID')
            if oid != SUBJECT_ALT_NAME:
                continue

            value = decoder.decode(extension.getComponentByName('extnValue'),
                               asn1Spec=OctetString())[0]
            sa_names = decoder.decode(value, asn1Spec=SubjectAltName())[0]
            for name in sa_names:
                name_type = name.getName()
                if name_type == 'dNSName':
                    results['DNS'].add(decode_str(name.getComponent()))
                if name_type == 'uniformResourceIdentifier':
                    value = decode_str(name.getComponent())
                    if value.startswith('xmpp:'):
                        results['URI'].add(value[5:])
                elif name_type == 'otherName':
                    name = name.getComponent()

                    oid = name.getComponentByName('type-id')
                    value = name.getComponentByName('value')

                    if oid == XMPP_ADDR:
                        value = decoder.decode(value, asn1Spec=UTF8String())[0]
                        results['XMPPAddr'].add(decode_str(value))
                    elif oid == SRV_NAME:
                        value = decoder.decode(value, asn1Spec=IA5String())[0]
                        results['SRV'].add(decode_str(value))
        return results


    def check_ca(self):
        for extension in self.extensions:
            oid = extension.getComponentByName('extnID')
            if oid != id_ce_basicConstraints:
                continue
            value = decoder.decode(extension.getComponentByName('extnValue'),
                               asn1Spec=OctetString())[0]
            constraints = decoder.decode(value, asn1Spec=BasicConstraints())[0]
            return bool(constraints[0])

    def extract_sig(self):
        signature = self.cert.getComponentByName('signatureValue')
        algorithm = self.cert.getComponentByName('signatureAlgorithm')
        data = encoder.encode(self.tbs)
        s = encoder.encode(signature)
        return algorithm, s, data


    def extract_pubkey(self):
        pki = self.tbs.getComponentByName('subjectPublicKeyInfo')
        algo = pki.getComponentByName('algorithm')
        algorithm = algo.getComponentByName('algorithm')
        parameters = algo.getComponentByName('parameters')
        subjectPublicKey = pki.getComponentByName('subjectPublicKey')
        return algorithm, parameters, encoder.encode(subjectPublicKey)


    def extract_dates(self):
        validity = self.tbs.getComponentByName('validity')
        not_before = validity.getComponentByName('notBefore')
        not_before = str(not_before.getComponent())
        not_after = validity.getComponentByName('notAfter')
        not_after = str(not_after.getComponent())
        if isinstance(not_before, GeneralizedTime):
            not_before = datetime.strptime(not_before, '%Y%m%d%H%M%SZ')
        else:
            not_before = datetime.strptime(not_before, '%y%m%d%H%M%SZ')
        if isinstance(not_after, GeneralizedTime):
            not_after = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
        else:
            not_after = datetime.strptime(not_after, '%y%m%d%H%M%SZ')
        return not_before, not_after

    def get_ttl(self):
        not_before, not_after = self.extract_dates()
        if not_after is None:
            return None
        return not_after - datetime.utcnow()

    def check_date(self):
        not_before, not_after = self.extract_dates()
        now = datetime.utcnow()
        if not_before > now:
            raise CertificateError(
                'Certificate has not entered its valid date range.')
        if not_after <= now:
            raise CertificateError(
                'Certificate has expired.')

    def check_name(self, expected):
        cert_names = self.extract_names()
        if '.' in expected:
            expected_wild = expected[expected.index('.'):]
        else:
            expected_wild = expected
        expected_srv = '_xmpp-client.%s' % expected
        for name in cert_names['XMPPAddr']:
            if name == expected:
                return True
        for name in cert_names['SRV']:
            if name == expected_srv or name == expected:
                return True
        for name in cert_names['DNS']:
            if name == expected:
                return True
            if name.startswith('*'):
                if '.' in name:
                    name_wild = name[name.index('.'):]
                else:
                    name_wild = name
                if expected_wild == name_wild:
                    return True
        for name in cert_names['URI']:
            if name == expected:
                return True
        if cert_names['CN'] == expected:
            return True
        raise CertificateError(
            'Could not match certficate against hostname: %s' % expected)


class X509CertChain(tlslite.X509CertChain):
    pass




def load_certificates(ca_path):
    ca_list = {}
    with open(ca_path, 'r') as f:
        s = f.read()
    bList = tlslite.utils.pem.dePemList(s, "CERTIFICATE")
    for b in bList:
        x = X509()
        try:
            x.parseBinary(b)
        except Exception as e:
            util.print_error("cannot parse cert:", e)
            continue
        ca_list[x.getFingerprint()] = x
    return ca_list
