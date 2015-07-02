import sys
import re
import dns
import traceback

import bitcoin
from util import StoreDict, print_error
from i18n import _

# Import all of the rdtypes, as py2app and similar get confused with the dnspython
# autoloader and won't include all the rdatatypes
try:
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
    OA_READY = True
except ImportError:
    OA_READY = False


class Contacts(StoreDict):

    def __init__(self, config):
        StoreDict.__init__(self, config, 'contacts')

    def resolve(self, k):
        if bitcoin.is_address(k):
            return {
                'address': k,
                'type': 'address'
            }

        if k in self.keys():
            _type, addr = self[k]
            if _type == 'address':
                return {
                    'address': addr,
                    'type': 'contact'
                }

        out = self.resolve_openalias(k)
        if out:
            address, name = out
            try:
                validated = self.validate_dnssec(k)
            except:
                validated = False
                traceback.print_exc(file=sys.stderr)
            return {
                'address': address,
                'name': name,
                'type': 'openalias',
                'validated': validated
            }

        raise Exception("Invalid Litecoin address or alias", k)

    def resolve_openalias(self, url):
        '''Resolve OpenAlias address using url.'''
        print_error('[OA] Attempting to resolve OpenAlias data for ' + url)

        url = url.replace('@', '.')  # support email-style addresses, per the OA standard
        prefix = 'ltc'
        retries = 3
        err = None
        for i in range(0, retries):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 4.0
                records = resolver.query(url, dns.rdatatype.TXT)
                for record in records:
                    string = record.strings[0]
                    if string.startswith('oa1:' + prefix):
                        address = self.find_regex(string, r'recipient_address=([A-Za-z0-9]+)')
                        name = self.find_regex(string, r'recipient_name=([^;]+)')
                        if not name:
                            name = address
                        if not address:
                            continue
                        return (address, name)
                err = _('No OpenAlias record found.')
                break
            except dns.resolver.NXDOMAIN:
                err = _('No such domain.')
                continue
            except dns.resolver.Timeout:
                err = _('Timed out while resolving.')
                continue
            except DNSException:
                err = _('Unhandled exception.')
                continue
            except Exception, e:
                err = _('Unexpected error: ' + str(e))
                continue
            break
        if err:
            print_error(err)
        return 0

    def find_regex(self, haystack, needle):
        regex = re.compile(needle)
        try:
            return regex.search(haystack).groups()[0]
        except AttributeError:
            return None

    def validate_dnssec(self, url):
        print_error('Checking DNSSEC trust chain for ' + url)
        default = dns.resolver.get_default_resolver()
        ns = default.nameservers[0]
        parts = url.split('.')

        for i in xrange(len(parts), 0, -1):
            sub = '.'.join(parts[i - 1:])
            query = dns.message.make_query(sub, dns.rdatatype.NS)
            response = dns.query.udp(query, ns, 3)
            if response.rcode() != dns.rcode.NOERROR:
                print_error("query error")
                return False

            if len(response.authority) > 0:
                rrset = response.authority[0]
            else:
                rrset = response.answer[0]

            rr = rrset[0]
            if rr.rdtype == dns.rdatatype.SOA:
                #Same server is authoritative, don't check again
                continue

            query = dns.message.make_query(sub,
                                           dns.rdatatype.DNSKEY,
                                           want_dnssec=True)
            response = dns.query.udp(query, ns, 3)
            if response.rcode() != 0:
                self.print_error("query error")
                return False
                # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)

            # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
            answer = response.answer
            if len(answer) != 2:
                print_error("answer error", answer)
                return False

            # the DNSKEY should be self signed, validate it
            name = dns.name.from_text(sub)
            try:
                dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
            except dns.dnssec.ValidationFailure:
                print_error("validation error")
                return False

        return True
