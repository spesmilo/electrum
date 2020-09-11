PACKAGE_VERSION  = '4.1.1'  # version of the client package
PROTOCOL_VERSION = '1.4'     # protocol version requested

# The hash of the Electrum mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet, Electrum seed


def seed_prefix(seed_type):
    assert seed_type in ('standard', 'electrum')
    return SEED_PREFIX

import re

_RX_NORMALIZER = re.compile(r'(\.0+)*$')
_RX_VARIANT_TOKEN_PARSE = re.compile(r'^(\d+)(.+)$')

def normalize_version(v):
    """Used for PROTOCOL_VERSION normalization, e.g '1.4.0' -> (1,4) """
    return tuple(int(x) for x in _RX_NORMALIZER.sub('', v.strip()).split("."))

def parse_package_version(pvstr):
    """ Basically returns a tuple of the normalized version plus the 'variant'
    string at the end. Eg '3.3.0' -> (3, 3, ''), '3.2.2CS' -> (3, 2, 2, 'CS'),
    etc.

    Some more examples:
            '3.3.5CS' -> (3, 3, 5, 'CS')
            '3.4.5_iOS' -> (3, 4, 5, '_iOS')
            '3.3.5' -> (3, 3, 5, '')
            '3.3' -> (3, 3, '')
            '3.3.0' -> (3, 3, '')
            '   3.2.2.0 ILikeSpaces ' -> (3, 2, 2, 'ILikeSpaces')
    Note how 0 fields at the end of the version get normalized with the 0 lopped off:
            '3.3.0' -> (3, 3, '')
            '3.5.0.0.0' -> (3, 5, '')
            '3.5.0.0.0_iOS' -> (3, 5, '_iOS')
    ... and, finally: The last element is *always* going to be present as
    a string, the 'variant'. The 'variant' will be the empty string '' if
    this is the default Electron Cash. If you don't like this heterogeneity of
    types in a tuple, take the retVal[:-1] slice of the array to toss it
    (or just use normalize_version above).
    """
    def raise_(e=None):
        exc = ValueError('Failed to parse package version for: "{}"'.format(pvstr))
        if e: raise exc from e
        else: raise exc
    toks = [x.strip() for x in pvstr.split(".")]
    if not toks:
        raise_()
    if toks[-1].isdigit():
        # Missing 'variant' at end.. add the default '' variant.
        toks.append('')
    else:
        # had 'variant' at end, parse it.
        m = _RX_VARIANT_TOKEN_PARSE.match(toks[-1])
        if m:
            # pop off end and...
            toks[-1:] = [m.group(1), # add the digit portion back (note it's still a str at this point)
                         m.group(2).strip()] # add the leftovers as the actual variant
        else:
            raise_()
    try:
        # make sure everything but the last element is an int.
        toks[:-1] = [int(x) for x in toks[:-1]]
    except ValueError as e:
        raise_(e)
    # .. and.. finally: Normalize it! (lopping off zeros at the end)
    toks[:-1] = normalize_version('.'.join(str(t) for t in toks[:-1]))
    return tuple(toks)
