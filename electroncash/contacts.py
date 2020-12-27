##!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
import dns
from dns.exception import DNSException
import json
import os
import re
import traceback
from collections import namedtuple
from typing import List, Dict, Generator
from . import dnssec
from . import cashacct
from . import util
from . import networks
from .storage import WalletStorage
from .address import Address

class Contact(namedtuple("Contact", "name address type")):
    ''' Your basic contacts entry. '''

contact_types = {'address', 'cashacct', 'openalias'}

class Contacts(util.PrintError):
    '''Electron Cash Contacts subsystem 2.0. Lightweight class for saving/laoding
    contacts to/from storage. This system replaces the old system which was
    a dict keyed off address, and which was limited to 1 contact per address
    and thus unusable for Cash Accounts and other features.

    Instead we model the contact list as a list, keyed off index. Multiple
    entries with the same name or address in the list are ok now. '''

    def __init__(self, storage: WalletStorage):
        assert isinstance(storage, WalletStorage)
        self.storage = storage
        self.load()  # NB: sets up self.data


    ##########################################
    # Load / Save plus their private methods #
    ##########################################

    def load(self):
        self.data = self._load_from_dict_like_object(self.storage)

    @staticmethod
    def _load_from_dict_like_object(storage) -> List[Contact]:
        assert callable(getattr(storage, 'get', None))
        l = storage.get('contacts2')
        v2_was_missing = not isinstance(l, list)
        # Check if v2 missing but v1 available.  If so, load v1 data.
        # Next time save() is called, wallet storage will have v2 data
        # and this branch will be ignored.
        if v2_was_missing and isinstance(storage.get('contacts'), dict):
            return Contacts._loadv1(storage)

        if v2_was_missing:
            # if we get here, neither v1 nor v2 was found, return empty list
            return []

        return Contacts._load_v2_list(l)

    @staticmethod
    def _load_v2_list(in_list):
        out = []
        for d in in_list:
            if not isinstance(d, dict):
                continue  # skip obviously bad entries
            name, address, typ = d.get('name'), d.get('address'), d.get('type')
            if not all(isinstance(a, str) for a in (name, address, typ)):
                continue # skip invalid-looking data
            address = __class__._cleanup_address(address, typ)
            if typ in ('address', 'cashacct'):
                if not Address.is_valid(address) or (typ == 'cashacct' and not cashacct.CashAcct.parse_string(name)):
                    continue # skip if if does not appear to be valid for these types
            out.append( Contact(name, address, typ) )
        return out

    @staticmethod
    def _loadv1(storage) -> List[Contact]:
        ''' loads v1 'contacts' key from `storage`, which should be either a
        dict or WalletStorage; it must simply support the dict-like method
        'get'. Note this also supports the pre-v1 format, as the old Contacts
        class did. '''
        assert callable(getattr(storage, 'get', None))
        d = dict()
        d2 = storage.get('contacts')
        try:
            d.update(d2)  # catch type errors, etc by doing this
        except:
            return []
        data = []
        # backward compatibility
        for k, v in d.copy().items():
            try:
                _type, n = v
            except:
                continue
            # Previous to 1.0 the format was { name : (type, address) }
            #          -> current 1.0 format { address : (type, name) }
            if _type == 'address' and Address.is_valid(n) and not Address.is_valid(k):
                d.pop(k)
                d[n] = ('address', k)
        # At this point d is the v1 style contacts dict, just put it in data
        for address, tup in d.items():
            _type, name = tup
            if _type == 'address' and not Address.is_valid(address):
                # skip invalid v1 entries, for sanity.
                continue
            if _type not in contact_types:
                # not a known type we care about
                continue
            address = __class__._cleanup_address(address, _type)
            data.append(
                Contact(str(name), str(address), str(_type))
            )
        return data

    @staticmethod
    def _cleanup_address(address : str, _type : str) -> str:
        rm_prefix = (networks.net.CASHADDR_PREFIX + ":").lower()
        if _type in ('address', 'cashacct') and address.lower().startswith(rm_prefix):
            address = address[len(rm_prefix):]  # chop off bitcoincash: prefix
        return address

    @staticmethod
    def _save(data : List[Contact], v1_too : bool = False) -> dict:
        ''' Re-usable save methods. Saves keys to a dict, which can then
        be saved to wallet storage or saved to json. '''
        out_v2, out_v1, ret = [], {}, {}
        for contact in data:
            out_v2.append({
                'name': contact.name,
                'address': contact.address,
                'type': contact.type
            })
            if v1_too:
                # NOTE: v1 doesn't preserve dupe addresses
                out_v1[contact.address] = (contact.type, contact.name)

        ret['contacts2'] = out_v2

        if v1_too:
            ret['contacts'] = out_v1

        return ret

    def save(self):
        d = self._save(self.data, v1_too = False)  # Note: set v1_too = True if you want to save to v1 so older EC wallets can also see the updated contacts
        for k,v in d.items():
            self.storage.put(k, v)  # "contacts2", "contacts" are the two expected keys

    ######################
    # Import/Export File #
    ######################
    def import_file(self, path : str) -> int:
        ''' Import contacts from a file. The file should contain a JSON dict.
        Old-style pre-4.0.8 contact export .json files are supported and
        auto-detected, as well as new-style 4.0.8+ files. '''
        count = 0
        try:
            with open(path, 'r', encoding='utf-8') as f:
                d = json.loads(f.read())
                if not isinstance(d, dict):
                    raise RuntimeError(f"Expected a JSON dict in file {os.path.basename(path)}, instead got {str(type(d))}")
                if not 'contacts' in d and not 'contacts2' in d:
                    # was old-style export from pre 4.0.8 EC JSON dict
                    d = { 'contacts' : d }  # make it look like a dict with 'contacts' in it so that it resembles a wallet file, and next call to _load_from_dict_like_object works
                contacts = self._load_from_dict_like_object(d)
                for contact in contacts:
                    res = self.add(contact, unique=True)  # enforce unique imports in case user imports the same file multiple times
                    if res:
                        count += 1
        except:
            self.print_error(traceback.format_exc())
            raise
        if count:
            self.save()
        return count

    def export_file(self, path : str) -> int:
        ''' Save contacts as JSON to a file. May raise OSError. The contacts
        are saved in such a format that they are readable by both EC 4.0.8 and
        prior versions (contains legacy as well as new versions of the data
        in a large JSON dict).'''
        d = self._save(self.data, v1_too = True)
        with open(path, 'w+', encoding='utf-8') as f:
            json.dump(d, f, indent=4, sort_keys=True)
        return len(self.data)

    #####################
    # OpenAlias-related #
    #####################

    def resolve(self, k):
        if Address.is_valid(k):
            return {
                'address': Address.from_string(k),
                'type': 'address'
            }
        ''' The below was commented-out but was translated as a work-alike
        from the old contacts class. I can't figure out what purpose it serves
        and looks like a way to support old legacy code that swappd
        address for name.  We will leave this commented-out, but it's here
        in case I discover later this code path actually was useful to some
        client code somewhere. -Calin '''
        '''
        def find_address(k):
            for contact in self.data:
                if k == contact.address:
                    return contact
        # FIXME: this looks way broken. Basically translated from old contacts class... -Calin
        contact = find_address(k)
        if contact:
            _type, addr = contact.type, contact.name  #  <-- looks broken, FIXME (was what we had in old_contacts). TODO: Figure this out
            if _type == 'address':
                return {
                    'address': addr,  # why would the name be placed in 'address' in this dict?! -Calin
                    'type': 'contact'  # where would this ever be used?? -Calin
                }
        '''
        out = self.resolve_openalias(k)
        if out:
            address, name, validated = out
            return {
                'address': address,
                'name': name,
                'type': 'openalias',
                'validated': validated
            }
        raise RuntimeWarning("Invalid Bitcoin address or alias", k)

    @classmethod
    def resolve_openalias(cls, url):
        # support email-style addresses, per the OA standard
        url = url.replace('@', '.')
        try:
            records, validated = dnssec.query(url, dns.rdatatype.TXT)
        except DNSException as e:
            util.print_error('[Contacts] Error resolving openalias: ', str(e))
            return None
        prefix = 'bch'
        for record in records:
            string = record.strings[0].decode('utf-8')
            if string.startswith('oa1:' + prefix):
                address = cls.find_regex(string, r'recipient_address=([A-Za-z0-9]+)')
                name = cls.find_regex(string, r'recipient_name=([^;]+)')
                if not name:
                    name = address
                if not address:
                    continue
                return Address.from_string(address), name, validated

    @staticmethod
    def find_regex(haystack, needle):
        regex = re.compile(needle)
        try:
            return regex.search(haystack).groups()[0]
        except AttributeError:
            return None


    ###############
    # Plublic API #
    ###############

    def has(self, contact : Contact) -> bool:
        ''' returns True iff contact is in our contacts list '''
        return contact in self.data

    @property
    def empty(self) -> bool:
        return not self.data  # True if [] or None, although data shouldn't ever be None

    @property
    def num(self) -> int:
        return len(self.data)

    def get_all(self, nocopy : bool = False) -> List[Contact]:
        ''' Returns a copy of the internal Contact list. '''
        if nocopy:
            return self.data
        return self.data.copy()

    def replace(self, old : Contact, new : Contact):
        ''' Replaces existing contact old with a new one. Will not add if old
        is not found. Returns True on success or False on error. '''
        assert isinstance(new, Contact)
        try:
            index = self.data.index(old)
            self.data[index] = new
            self.save()
            return True
        except ValueError:
            pass
        return False

    def add(self, contact : Contact, replace_old : Contact = None, unique : bool = False,
            save : bool = True) -> bool:
        ''' Puts a contact in the contact list, appending it at the end.
        Optionally, if replace_old is specified, will replace the entry
        where replace_old resides.  If replace_old cannot be found, will simply
        put the contact at the end.

        If unique is True, will not add if the contact already exists (useful
        for importing where you don't want multiple imports of the same contact
        file to keep growing the contact list).
        '''
        assert isinstance(contact, Contact) and isinstance(replace_old, (Contact, type(None)))
        if replace_old:
            success = self.replace(replace_old, contact)
            if success:
                return True
            else:
                ''' replace_old not found, proceed to just add to end '''
                self.print_error(f"add: replace_old={replace_old} not found in contacts")
        if unique and contact in self.data:
            return False  # unique add requested, abort because already exists
        self.data.append(contact)
        if save:
            self.save()
        return True

    def remove(self, contact : Contact, save : bool = True) -> bool:
        ''' Removes a contact from the contact list. Returns True if it was
        removed or False otherwise. Note that if multiple entries for the same
        contact exist, only the first one found is removed. '''
        try:
            self.data.remove(contact)
            if save:
                self.save()
            return True
        except ValueError:
            return False

    def remove_all(self, contact : Contact) -> int:
        ''' Removes all entries matching contact from the internal contact list.
        Returns the number of entries removed successfully. '''
        ct = 0
        while self.remove(contact, save=False):
            ct += 1
        if ct:
            self.save()
        return ct

    def find(self, *, address: str = None, name: str = None, type: str = None,
             case_sensitive: bool = True) -> Generator[Contact, None, None]:
        ''' Returns a generator. Searches the contact list for contacts matching
        the specs given. Note that specifying no args will simply return all
        contacts via a generator '''
        if not case_sensitive and name is not None:
            name = name.lower()
        for c in self.data:
            if address is not None and c.address != address:
                continue
            if not case_sensitive:
                if name is not None and c.name.lower() != name:
                    continue
            else:
                if name is not None and c.name != name:
                    continue
            if type is not None and c.type != type:
                continue
            yield c
