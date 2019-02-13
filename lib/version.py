PACKAGE_VERSION  = '3.3.6'   # version of the client package
PROTOCOL_VERSION = '1.4'     # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet


def seed_prefix(seed_type):
    assert seed_type == 'standard'
    return SEED_PREFIX

import re

_RX_VERSION_PARSE = re.compile(r'(\d+)[.](\d+)[.]?(\d*)\s*(\S*)')
_RX_NORMALIZER = re.compile(r'(\.0+)*$')

def parse_package_version(pvstr):
    """
    Parse a package version string e.g.:
        '3.3.5CS' -> (3, 3, 5, 'CS')
        '3.4.5_iOS' -> (3, 4, 5, '_iOS')
        '3.3.5' -> (3, 3, 5, '')
        '3.3' -> (3, 3, 0, '')
        and.. perhaps unexpectedly:
        '3.3.5.1_iOS' -> (3, 3, 5, '.1_iOS') .. so be sure not to have more than 3 version fields + 1 'extra' field!
        etc...
    """
    m = _RX_VERSION_PARSE.search(pvstr)
    if not m:
        raise ValueError('Failed to parse package version for: ' + str(pvstr))
    major, minor, rev, variant = int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)
    rev = int(rev) if rev else 0
    return major, minor, rev, variant

def normalize_version(v):
    """Used for PROTOCOL_VERSION normalization, e.g '1.4.0' -> (1,4) """
    return tuple(int(x) for x in _RX_NORMALIZER.sub('', v.strip()).split("."))

