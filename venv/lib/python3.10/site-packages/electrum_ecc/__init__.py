from .keys import *
from .ecdsa_sigformat import *
from .util import *
from .ecc_fast import _libsecp256k1


__version__ = '0.0.6'


# Some unit tests need to create ECDSA sigs without grinding the R value (and just use RFC6979).
# see https://github.com/bitcoin/bitcoin/pull/13666
ENABLE_ECDSA_R_VALUE_GRINDING = True
