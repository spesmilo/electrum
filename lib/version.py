PACKAGE_VERSION = '3.3.2'     # version of the client package
PROTOCOL_VERSION = '1.4'     # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet


def seed_prefix(seed_type):
    assert seed_type == 'standard'
    return SEED_PREFIX
