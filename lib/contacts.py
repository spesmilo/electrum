import sys
import re
import dns
import traceback

import bitcoin
from util import StoreDict, print_error
from i18n import _

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
            validated = False
            return {
                'address': address,
                'name': name,
                'type': 'openalias',
                'validated': validated
            }

        raise Exception("Invalid Bitcoin address or alias", k)

    def resolve_openalias(self, url):
        '''Resolve OpenAlias address using url.'''
        print_error('[OA] Attempting to resolve OpenAlias data for ' + url)

        url = url.replace('@', '.')  # support email-style addresses, per the OA standard
        prefix = 'btc'
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

