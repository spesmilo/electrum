#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

# Check DNSSEC trust chain.
# Todo: verify expiration dates
#
# Based on
#  http://backreference.org/2010/11/17/dnssec-verification-with-dig/
#  https://github.com/rthalley/dnspython/blob/master/tests/test_dnssec.py


# import traceback
# import sys
import time
import struct
import hashlib


import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.DLV
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import dns.rdtypes.ANY.NSEC3PARAM
import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA

from .logging import get_logger


_logger = get_logger(__name__)


# hard-coded trust anchors (root KSKs)
trust_anchors = [
    # KSK-2017:
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU='),
    # KSK-2010:
    dns.rrset.from_text('.', 15202, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0='),
]


def check_query(ns, sub, _type, keys):
    q = dns.message.make_query(sub, _type, want_dnssec=True)
    response = dns.query.tcp(q, ns, timeout=5)
    assert response.rcode() == 0, 'No answer'
    answer = response.answer
    assert len(answer) != 0, ('No DNS record found', sub, _type)
    assert len(answer) != 1, ('No DNSSEC record found', sub, _type)
    if answer[0].rdtype == dns.rdatatype.RRSIG:
        rrsig, rrset = answer
    elif answer[1].rdtype == dns.rdatatype.RRSIG:
        rrset, rrsig = answer
    else:
        raise Exception('No signature set in record')
    if keys is None:
        keys = {dns.name.from_text(sub):rrset}
    dns.dnssec.validate(rrset, rrsig, keys)
    return rrset


def get_and_validate(ns, url, _type):
    # get trusted root key
    root_rrset = None
    for dnskey_rr in trust_anchors:
        try:
            # Check if there is a valid signature for the root dnskey
            root_rrset = check_query(ns, '', dns.rdatatype.DNSKEY, {dns.name.root: dnskey_rr})
            break
        except dns.dnssec.ValidationFailure:
            # It's OK as long as one key validates
            continue
    if not root_rrset:
        raise dns.dnssec.ValidationFailure('None of the trust anchors found in DNS')
    keys = {dns.name.root: root_rrset}
    # top-down verification
    parts = url.split('.')
    for i in range(len(parts), 0, -1):
        sub = '.'.join(parts[i-1:])
        name = dns.name.from_text(sub)
        # If server is authoritative, don't fetch DNSKEY
        query = dns.message.make_query(sub, dns.rdatatype.NS)
        response = dns.query.udp(query, ns, 3)
        assert response.rcode() == dns.rcode.NOERROR, "query error"
        rrset = response.authority[0] if len(response.authority) > 0 else response.answer[0]
        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            continue
        # get DNSKEY (self-signed)
        rrset = check_query(ns, sub, dns.rdatatype.DNSKEY, None)
        # get DS (signed by parent)
        ds_rrset = check_query(ns, sub, dns.rdatatype.DS, keys)
        # verify that a signed DS validates DNSKEY
        for ds in ds_rrset:
            for dnskey in rrset:
                htype = 'SHA256' if ds.digest_type == 2 else 'SHA1'
                good_ds = dns.dnssec.make_ds(name, dnskey, htype)
                if ds == good_ds:
                    break
            else:
                continue
            break
        else:
            raise Exception("DS does not match DNSKEY")
        # set key for next iteration
        keys = {name: rrset}
    # get TXT record (signed by zone)
    rrset = check_query(ns, url, _type, keys)
    return rrset


def query(url, rtype):
    # 8.8.8.8 is Google's public DNS server
    nameservers = ['8.8.8.8']
    ns = nameservers[0]
    try:
        out = get_and_validate(ns, url, rtype)
        validated = True
    except BaseException as e:
        _logger.info(f"DNSSEC error: {repr(e)}")
        out = dns.resolver.resolve(url, rtype)
        validated = False
    return out, validated
