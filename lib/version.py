PACKAGE_VERSION  = '3.3.5'   # version of the client package
PROTOCOL_VERSION = '1.4'     # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet


def seed_prefix(seed_type):
    assert seed_type == 'standard'
    return SEED_PREFIX

def parse_package_version(pvstr):
    """
    Parse a package version string e.g.:
        '3.3.5CS' -> (3, 3, 5, 'CS')
        '3.4.5_iOS' -> (3, 4, 5, '_iOS')
        '3.3.5' -> (3, 3, 5, '')
        '3.3' -> (3, 3, 0, '')
        etc...
    """
    import re
    m = re.search(r'(\d+)[.](\d+)[.]?(\d*)\s*(\S*)', pvstr)
    if not m:
        raise ValueError('Failed to parse package version for: ' + str(pvstr))
    major, minor, rev, variant = int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)
    rev = int(rev) if rev else 0
    return major, minor, rev, variant
