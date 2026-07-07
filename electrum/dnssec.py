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

import logging

import dns
import dns.name
import dns.asyncquery
import dns.dnssec
import dns.exception
import dns.message
import dns.asyncresolver
import dns.resolver
import dns.rcode
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
from typing import Tuple, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .network import ProxySettings


_logger = get_logger(__name__)


# hard-coded trust anchors (root KSKs)
TRUST_ANCHORS = [
    # KSK-2017:
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU='),
    # KSK-2010:
    dns.rrset.from_text('.', 15202, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0='),
]


# public fallback nameserver, used only if the system/DHCP resolver cannot be determined
# (e.g. no /etc/resolv.conf, some mobile setups). Google Public DNS.
FALLBACK_NAMESERVER = '8.8.8.8'


class DNSTransport:
    """Delegate that decides how a single DNS query message is sent and answered.

    The DNSSEC logic downstream is transport-agnostic: it builds query messages and
    hands them to a transport..
    """

    async def send(self, q: dns.message.Message) -> dns.message.Message:
        raise NotImplementedError


class LocalTransport(DNSTransport):
    """Plain DNS to the system (DHCP-provided) nameserver over UDP, falling back to
    TCP on truncation (DNSSEC responses are large and routinely get truncated).
    Used when no proxy is configured."""

    def __init__(self, nameserver: Optional[str] = None):
        self.nameserver = nameserver or _system_nameserver()

    async def send(self, q: dns.message.Message) -> dns.message.Message:
        response, _used_tcp = await dns.asyncquery.udp_with_fallback(q, self.nameserver, timeout=5)
        return response


class DoHTransport(DNSTransport):
    """DNS-over-HTTPS, tunneled through the proxy via Network.async_send_http_on_proxy
    (aiohttp + SOCKS, with rdns so the DoH hostname is resolved through the proxy).
    Used when a proxy is configured: SOCKS cannot carry UDP, its RESOLVE command cannot
    transport TXT records, nor the DNSSEC records we need for verification. We run real
    DNS over an HTTPS stream through the proxy instead."""

    def __init__(self, doh_endpoint: str):
        self.doh_endpoint = doh_endpoint

    async def send(self, q: dns.message.Message) -> dns.message.Message:
        from .network import Network

        async def on_finish(resp):
            resp.raise_for_status()
            return await resp.read()

        raw = await Network.async_send_http_on_proxy(
            'post', self.doh_endpoint,
            body=q.to_wire(),
            headers={
                'content-type': 'application/dns-message',
                'accept': 'application/dns-message',
            },
            on_finish=on_finish,
            timeout=5,
        )
        return dns.message.from_wire(raw)


def _system_nameserver() -> str:
    # the DHCP/OS-provided resolver(s), as dnspython reads them from the system config
    try:
        nameservers = dns.resolver.get_default_resolver().nameservers
    except Exception as e:
        _logger.info(f"could not determine system nameserver, using fallback: {e!r}")
        nameservers = None
    return nameservers[0] if nameservers else FALLBACK_NAMESERVER


def _make_transport(proxy: Optional['ProxySettings']) -> DNSTransport:
    if proxy is not None and proxy.enabled and proxy.doh_endpoint:
        return DoHTransport(proxy.doh_endpoint)
    return LocalTransport()


async def _check_query(transport: DNSTransport, sub, _type, keys) -> dns.rrset.RRset:
    q = dns.message.make_query(sub, _type, want_dnssec=True)
    response = await transport.send(q)
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


async def _get_and_validate(transport: DNSTransport, url, _type) -> dns.rrset.RRset:
    # get trusted root key
    root_rrset = None
    for dnskey_rr in TRUST_ANCHORS:
        try:
            # Check if there is a valid signature for the root dnskey
            root_rrset = await _check_query(transport, '', dns.rdatatype.DNSKEY, {dns.name.root: dnskey_rr})
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
        response = await transport.send(query)
        assert response.rcode() == dns.rcode.NOERROR, "query error"
        rrset = response.authority[0] if len(response.authority) > 0 else response.answer[0]
        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            continue
        # get DNSKEY (self-signed)
        rrset = await _check_query(transport, sub, dns.rdatatype.DNSKEY, None)
        # get DS (signed by parent)
        ds_rrset = await _check_query(transport, sub, dns.rdatatype.DS, keys)
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
    rrset = await _check_query(transport, url, _type, keys)
    return rrset


async def _resolve_unvalidated(transport: DNSTransport, url, rtype) -> dns.rrset.RRset:
    """Plain (non-DNSSEC) resolution, over the same transport so a proxied user does
    not leak DNS via the system resolver."""
    response = await transport.send(dns.message.make_query(url, rtype))
    if response.rcode() != dns.rcode.NOERROR:
        raise dns.exception.DNSException(f"query error: rcode={response.rcode()}")
    for rrset in response.answer:
        if rrset.rdtype == rtype:
            return rrset
    raise dns.exception.DNSException(f"no {dns.rdatatype.to_text(rtype)} answer for {url!r}")


async def query(
    url: str,
    rtype: dns.rdatatype.RdataType,
    *,
    proxy: Optional['ProxySettings'] = None,
) -> Tuple[dns.rrset.RRset, bool]:
    """Try to do DNS resolution, including DNSSEC.
    'validated' shows whether the DNSSEC checks passed. DNS is completely INSECURE without DNSSEC,
    so the caller must carefully consider whether the response can be used for anything if validated=False.

    The transport is chosen from the proxy settings: without a proxy we query the system
    (DHCP-provided) nameserver directly over UDP/TCP; with a proxy we run DNS-over-HTTPS
    tunneled through it (SOCKS cannot carry UDP, and Tor's RESOLVE extension supports
    neither TXT nor DNSSEC). The DoH endpoint is taken from ProxySettings.doh_endpoint.
    """
    if proxy is None:
        from .network import Network
        network = Network.get_instance()
        proxy = network.proxy if network else None
    transport = _make_transport(proxy)
    try:
        out = await _get_and_validate(transport, url, rtype)
        validated = True
    except Exception as e:
        log_level = logging.WARNING if isinstance(e, ImportError) else logging.INFO
        _logger.log(log_level, f"DNSSEC error: {repr(e)}")
        out = await _resolve_unvalidated(transport, url, rtype)
        validated = False
    return out, validated
