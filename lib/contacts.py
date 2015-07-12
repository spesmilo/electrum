import sys
import re
import dns

import bitcoin
import dnssec
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
            address, name, validated = out
            return {
                'address': address,
                'name': name,
                'type': 'openalias',
                'validated': validated
            }
        raise Exception("Invalid Litecoin address or alias", k)

    def resolve_openalias(self, url):
        # support email-style addresses, per the OA standard
        url = url.replace('@', '.')
        try:
            records, validated = dnssec.query(url, dns.rdatatype.TXT)
        except:
            return
        prefix = 'ltc'
        for record in records:
            string = record.strings[0]
            if string.startswith('oa1:' + prefix):
                address = self.find_regex(string, r'recipient_address=([A-Za-z0-9]+)')
                name = self.find_regex(string, r'recipient_name=([^;]+)')
                if not name:
                    name = address
                if not address:
                    continue
                return address, name, validated

    def find_regex(self, haystack, needle):
        regex = re.compile(needle)
        try:
            return regex.search(haystack).groups()[0]
        except AttributeError:
            return None

