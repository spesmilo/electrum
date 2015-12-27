from plugins.trezor.client import trezor_client_class
from plugins.trezor.plugin import TrezorCompatiblePlugin, TrezorCompatibleWallet

try:
    from keepkeylib.client import proto, BaseClient, ProtocolMixin
    KEEPKEY = True
except ImportError:
    KEEPKEY = False


class KeepKeyWallet(TrezorCompatibleWallet):
    wallet_type = 'keepkey'
    device = 'KeepKey'


class KeepKeyPlugin(TrezorCompatiblePlugin):
    client_class = trezor_client_class(ProtocolMixin, BaseClient, proto)
    firmware_URL = 'https://www.keepkey.com'
    libraries_URL = 'https://github.com/keepkey/python-keepkey'
    libraries_available = KEEPKEY
    minimum_firmware = (1, 0, 0)
    wallet_class = KeepKeyWallet
    import keepkeylib.ckd_public as ckd_public
    from keepkeylib.client import types
    from keepkeylib.transport_hid import HidTransport
