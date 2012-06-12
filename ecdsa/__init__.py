
from keys import SigningKey, VerifyingKey, BadSignatureError, BadDigestError
from curves import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p

_hush_pyflakes = [SigningKey, VerifyingKey, BadSignatureError, BadDigestError,
                  NIST192p, NIST224p, NIST256p, NIST384p, NIST521p]
del _hush_pyflakes

# This code comes from http://github.com/warner/python-ecdsa

try:
    from _version import __version__ as v
    __version__ = v
    del v
except ImportError:
    __version__ = "UNKNOWN"
