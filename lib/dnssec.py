#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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



# Check DNSSEC trust chain.
# Todo: verify expiration dates
#
# Based on
#  http://backreference.org/2010/11/17/dnssec-verification-with-dig/
#  https://github.com/rthalley/dnspython/blob/master/tests/test_dnssec.py
 

import traceback
import sys

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
from dns.exception import DNSException


from util import print_error


# hard-coded root KSK
root_KSK = dns.rrset.from_text('.', 15202, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=')



def check_query(ns, sub, _type, keys):
    q = dns.message.make_query(sub, _type, want_dnssec=True)
    response = dns.query.tcp(q, ns, timeout=5)
    assert response.rcode() == 0, 'No answer'
    answer = response.answer
    assert len(answer) == 2, 'No DNSSEC record found'
    if answer[0].rdtype == dns.rdatatype.RRSIG:
        rrsig, rrset = answer
    else:
        rrset, rrsig = answer
    if keys is None:
        keys = {dns.name.from_text(sub):rrset}
    dns.dnssec.validate(rrset, rrsig, keys)
    return rrset


def get_and_validate(ns, url, _type):
    # get trusted root keys
    root_rrset = check_query(ns, '', dns.rdatatype.DNSKEY, {dns.name.root: root_KSK})
    keys = {dns.name.root: root_rrset}
    # top-down verification
    parts = url.split('.')
    for i in range(len(parts), 0, -1):
        sub = '.'.join(parts[i-1:])
        name = dns.name.from_text(sub)
        # get DNSKEY (self-signed)
        rrset = check_query(ns, sub, dns.rdatatype.DNSKEY, None)
        # get DS (signed by parent)
        ds_rrset = check_query(ns, sub, dns.rdatatype.DS, keys)
        # verify that a signed DS validates DNSKEY
        for ds in ds_rrset:
            for dnskey in rrset:
                good_ds = dns.dnssec.make_ds(name, dnskey, 'SHA256')
                if ds == good_ds:
                    break
            else:
                continue
            break
        else:
            print ds_rrset
            raise BaseException("DS does not match DNSKEY")
        # set key for next iteration
        keys = {name: rrset}
    # get TXT record (signed by zone)
    rrset = check_query(ns, url, _type, keys)
    return rrset


def query(url, rtype):
    resolver = dns.resolver.get_default_resolver()
    # 8.8.8.8 is Google's public DNS server
    resolver.nameservers = ['8.8.8.8']
    ns = resolver.nameservers[0]
    try:
        out = get_and_validate(ns, url, rtype)
        validated = True
    except BaseException as e:
        #traceback.print_exc(file=sys.stderr)
        print_error("DNSSEC error:", str(e))
        out = resolver.query(url, rtype)
        validated = False
    return out, validated
