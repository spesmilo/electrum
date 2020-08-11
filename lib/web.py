# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
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

import decimal # Qt 5.12 also exports Decimal, so take the package name
import os
import re
import shutil
import sys
import threading
import urllib

from .address import Address
from . import bitcoin
from . import networks
from .util import format_satoshis_plain, bh2u, bfh, print_error, do_in_main_thread
from . import cashacct
from .i18n import _


DEFAULT_EXPLORER = "Blockchair.com"

mainnet_block_explorers = {
    'Bitcoin.com': ('https://explorer.bitcoin.com/bch',
                    Address.FMT_CASHADDR,
                    {'tx': 'tx', 'addr': 'address', 'block' : 'block'}),
    'Blockchair.com': ('https://blockchair.com/bitcoin-cash',
                       Address.FMT_CASHADDR,
                       {'tx': 'transaction', 'addr': 'address', 'block' : 'block'}),
    'BTC.com': ('https://bch.btc.com',
                       Address.FMT_CASHADDR,
                       {'tx': '', 'addr': '', 'block' : 'block'}),
    'ViaBTC.com': ('https://explorer.viawallet.com/bch',
                   Address.FMT_CASHADDR,
                   {'tx': 'tx', 'addr': 'address', 'block' : 'block'}),
    'BlockExplorer.one': ('https://blockexplorer.one/bch/mainnet',
                   Address.FMT_CASHADDR,
                   {'tx': 'tx', 'addr': 'address', 'block' : 'blockHash'}),
    'electroncash.de': ('https://explorer.electroncash.de',
                        Address.FMT_CASHADDR,
                        {'tx': 'tx', 'addr': 'address', 'block': 'block-height'}),
    'Blockchain.com': ('https://www.blockchain.com/bch',
                       Address.FMT_CASHADDR,
                       {'tx': 'tx', 'addr': 'address', 'block': 'block'}),
}

DEFAULT_EXPLORER_TESTNET = 'Bitcoin.com'

testnet_block_explorers = {
    'Bitcoin.com'   : ('https://explorer.bitcoin.com/tbch',
                       Address.FMT_LEGACY,  # For some reason testnet expects legacy and fails on bchtest: addresses.
                       {'tx': 'tx', 'addr': 'address', 'block' : 'block'}),
    'BlockExplorer.one': ('https://blockexplorer.one/bch/testnet',
                   Address.FMT_CASHADDR,
                   {'tx': 'tx', 'addr': 'address', 'block' : 'blockHash'}),
    'electroncash.de': ('https://testnet-explorer.electroncash.de',
                        Address.FMT_CASHADDR,
                        {'tx': 'tx', 'addr': 'address', 'block': 'block-height'}),
    'Blockchain.com': ('https://www.blockchain.com/bch-testnet',
                       Address.FMT_CASHADDR,
                       {'tx': 'tx', 'addr': 'address', 'block': 'block'}),
}

def BE_info():
    if networks.net.TESTNET:
        return testnet_block_explorers
    return mainnet_block_explorers

def BE_tuple(config):
    infodict = BE_info()
    return (infodict.get(BE_from_config(config))
            or infodict.get(BE_default_explorer()) # In case block explorer in config is bad/no longer valid
           )

def BE_default_explorer():
    return (DEFAULT_EXPLORER
            if not networks.net.TESTNET
            else DEFAULT_EXPLORER_TESTNET)

def BE_from_config(config):
    return config.get('block_explorer', BE_default_explorer())

def BE_URL(config, kind, item):
    be_tuple = BE_tuple(config)
    if not be_tuple:
        return
    url_base, addr_fmt, parts = be_tuple
    kind_str = parts.get(kind)
    if kind_str is None:
        return
    if kind == 'addr':
        assert isinstance(item, Address)
        item = item.to_string(addr_fmt)
    return "/".join(part for part in (url_base, kind_str, item) if part)

def BE_sorted_list():
    return sorted(BE_info())

def _strip_cashacct_str(s: str) -> str:
    '''Strips emojis and ';' characters from a cashacct string
    of the form name#number[.123]'''
    return cashacct.CashAcct.strip_emoji(s).replace(';', '').strip()

def create_URI(addr, amount, message, *, op_return=None, op_return_raw=None, net=None):
    is_cashacct = bool(isinstance(addr, str) and cashacct.CashAcct.parse_string(addr))
    if not isinstance(addr, Address) and not is_cashacct:
        return ""
    if op_return is not None and op_return_raw is not None:
        raise ValueError('Must specify exactly one of op_return or op_return_hex as kwargs to create_URI')
    if is_cashacct:
        scheme, path = cashacct.URI_SCHEME, _strip_cashacct_str(addr)
    else:
        scheme, path = addr.to_URI_components(net=net)
    query = []
    if amount:
        query.append('amount=%s'%format_satoshis_plain(amount))
    if message:
        query.append('message=%s'%urllib.parse.quote(message))
    if op_return:
        query.append(f'op_return={str(op_return)}')
    if op_return_raw:
        query.append(f'op_return_raw={str(op_return_raw)}')
    p = urllib.parse.ParseResult(scheme=scheme,
                                 netloc='', path=path, params='',
                                 query='&'.join(query), fragment='')
    return urllib.parse.urlunparse(p)

def urlencode(s):
    ''' URL Encode; encodes a url or a uri fragment by %-quoting special chars'''
    return urllib.parse.quote(s)

def urldecode(url):
    ''' Inverse of urlencode '''
    return urllib.parse.unquote(url)

def parseable_schemes(net = None) -> tuple:
    if net is None:
        net = networks.net
    return (net.CASHADDR_PREFIX, cashacct.URI_SCHEME)

class ExtraParametersInURIWarning(RuntimeWarning):
    ''' Raised by parse_URI to indicate the parsing succeeded but that
    extra parameters were encountered when parsing.
    args[0] is the function return value (dict of parsed args).
    args[1:] are the URL parameters that were not understood (unknown params)'''

class DuplicateKeyInURIError(RuntimeError):
    ''' Raised on duplicate param keys in URI.
    args[0] is a translated error message suitable for the UI
    args[1:] is the list of duplicate keys. '''

class BadSchemeError(RuntimeError):
    ''' Raised if the scheme is bad/unknown for a URI. '''

class BadURIParameter(ValueError):
    ''' Raised if:
            - 'amount' is not numeric,
            - 'address' is invalid
            - bad cashacct string,
            - 'time' or 'exp' are not ints

        args[0] is the bad argument name e.g. 'amount'
        args[1] is the underlying Exception that was raised (if any, may be missing). '''

def parse_URI(uri, on_pr=None, *, net=None, strict=False, on_exc=None):
    """ If strict=True, may raise ExtraParametersInURIWarning (see docstring
    above).

    on_pr - a callable that will run in the context of a daemon thread if this
    is a payment request which requires further network processing. A single
    argument is passed to the callable, the payment request after being verified
    on the network. Note: as stated, this runs in the context of the daemon
    thread, unlike on_exc below.

    on_exc - (optional) a callable that will be executed in the *main thread*
    only in the cases of payment requests and only if they fail to serialize or
    deserialize. The callable must take 1 arg, a sys.exc_info() tuple. Note: as
    stateed, this runs in the context of the main thread always, unlike on_pr
    above.

    May raise DuplicateKeyInURIError if duplicate keys were found.
    May raise BadSchemeError if unknown scheme.
    May raise Exception subclass on other misc. failure.

    Returns a dict of uri_param -> value on success """
    if net is None:
        net = networks.net
    if ':' not in uri:
        # Test it's valid
        Address.from_string(uri, net=net)
        return {'address': uri}

    u = urllib.parse.urlparse(uri, allow_fragments=False)  # allow_fragments=False allows for cashacct:name#number URIs
    # The scheme always comes back in lower case
    accept_schemes = parseable_schemes(net=net)
    if u.scheme not in accept_schemes:
        raise BadSchemeError(_("Not a {schemes} URI").format(schemes=str(accept_schemes)))
    address = u.path

    is_cashacct = u.scheme == cashacct.URI_SCHEME

    # python for android fails to parse query
    if address.find('?') > 0:
        address, query = u.path.split('?')
        pq = urllib.parse.parse_qs(query, keep_blank_values=True)
    else:
        pq = urllib.parse.parse_qs(u.query, keep_blank_values=True)

    for k, v in pq.items():
        if len(v) != 1:
            raise DuplicateKeyInURIError(_('Duplicate key in URI'), k)

    out = {k: v[0] for k, v in pq.items()}
    if address:
        if is_cashacct:
            if '%' in address:
                # on macOS and perhaps other platforms the '#' character may
                # get passed-in as a '%23' if opened from a link or from
                # some other source.  The below call is safe and won't raise.
                address = urldecode(address)
            if not cashacct.CashAcct.parse_string(address):
                raise BadURIParameter('address', ValueError(_("{acct_name} is not a valid cashacct string").format(acct_name=address)))
            address = _strip_cashacct_str(address)
        else:
            # validate
            try: Address.from_string(address, net=net)
            except Exception as e: raise BadURIParameter('address', e) from e
        out['address'] = address

    if 'amount' in out:
        try:
            am = out['amount']
            m = re.match(r'([0-9.]+)X([0-9]{2})', am)
            if m:
                k = int(m.group(2)) - 8
                amount = decimal.Decimal(m.group(1)) * int(pow(10, k))
            else:
                amount = decimal.Decimal(am) * int(bitcoin.COIN)
            out['amount'] = int(amount)
        except (ValueError, decimal.InvalidOperation, TypeError) as e:
            raise BadURIParameter('amount', e) from e

    if strict and 'memo' in out and 'message' in out:
        # these two args are equivalent and cannot both appear together
        raise DuplicateKeyInURIError(_('Duplicate key in URI'), 'memo', 'message')
    elif 'message' in out:
        out['memo'] = out['message']
    elif 'memo' in out:
        out['message'] = out['memo']
    if 'time' in out:
        try: out['time'] = int(out['time'])
        except ValueError as e: raise BadURIParameter('time', e) from e
    if 'exp' in out:
        try: out['exp'] = int(out['exp'])
        except ValueError as e: raise BadURIParameter('exp', e) from e
    if 'sig' in out:
        try: out['sig'] = bh2u(bitcoin.base_decode(out['sig'], None, base=58))
        except Exception as e: raise BadURIParameter('sig', e) from e
    if 'op_return_raw' in out and 'op_return' in out:
        if strict:
            # these two args cannot both appear together
            raise DuplicateKeyInURIError(_('Duplicate key in URI'), 'op_return', 'op_return_raw')
        del out['op_return_raw']  # if not strict, just pick 1 and delete the other

    if 'op_return_raw' in out:
        # validate op_return_raw arg
        try: bfh(out['op_return_raw'])
        except Exception as e: raise BadURIParameter('op_return_raw', e) from e

    r = out.get('r')
    sig = out.get('sig')
    name = out.get('name')
    is_pr = bool(r or (name and sig))

    if is_pr and is_cashacct:
        raise ValueError(_("'{uri_scheme}' payment requests are not currently supported").format(uri_scheme=cashacct.URI_SCHEME))

    if on_pr and is_pr:
        def get_payment_request_thread():
            from . import paymentrequest as pr
            try:
                if name and sig:
                    s = pr.serialize_request(out).SerializeToString()
                    request = pr.PaymentRequest(s)
                else:
                    request = pr.get_payment_request(r)
            except:
                ''' May happen if the values in the request are such
                that they cannot be serialized to a protobuf. '''
                einfo = sys.exc_info()
                print_error("Error processing payment request:", str(einfo[1]))
                if on_exc:
                    do_in_main_thread(on_exc, einfo)
                return
            if on_pr:
                # FIXME: See about also making this use do_in_main_thread.
                # However existing code for Android and/or iOS may not be
                # expecting this, so we will leave the original code here where
                # it runs in the daemon thread context. :/
                on_pr(request)
        t = threading.Thread(target=get_payment_request_thread, daemon=True)
        t.start()
    if strict:
        accept_keys = {'r', 'sig', 'name', 'address', 'amount', 'label', 'message', 'memo', 'op_return', 'op_return_raw', 'time', 'exp'}
        extra_keys = set(out.keys()) - accept_keys
        if extra_keys:
            raise ExtraParametersInURIWarning(out, *tuple(extra_keys))
    return out

def check_www_dir(rdir):
    if not os.path.exists(rdir):
        os.mkdir(rdir)
    index = os.path.join(rdir, 'index.html')
    if not os.path.exists(index):
        print_error("copying index.html")
        src = os.path.join(os.path.dirname(__file__), 'www', 'index.html')
        shutil.copy(src, index)
    files = [
        "https://code.jquery.com/jquery-1.9.1.min.js",
        "https://raw.githubusercontent.com/davidshimjs/qrcodejs/master/qrcode.js",
        "https://code.jquery.com/ui/1.10.3/jquery-ui.js",
        "https://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css"
    ]
    for URL in files:
        path = urllib.parse.urlsplit(URL).path
        filename = os.path.basename(path)
        path = os.path.join(rdir, filename)
        if not os.path.exists(path):
            print_error("downloading ", URL)
            urllib.request.urlretrieve(URL, path)
