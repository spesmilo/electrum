from plugins.trezor.client import trezor_client_class
from plugins.trezor.plugin import TrezorCompatiblePlugin, TrezorCompatibleWallet

try:
    from trezorlib.client import proto, BaseClient, ProtocolMixin
    TREZOR = True
except ImportError:
    TREZOR = False


class TrezorWallet(TrezorCompatibleWallet):
    wallet_type = 'trezor'
    device = 'Trezor'


class TrezorPlugin(TrezorCompatiblePlugin):
    client_class = trezor_client_class(ProtocolMixin, BaseClient, proto)
    firmware_URL = 'https://www.mytrezor.com'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    libraries_available = TREZOR
    minimum_firmware = (1, 2, 1)
    wallet_class = TrezorWallet
    import trezorlib.ckd_public as ckd_public
    from trezorlib.client import types
    from trezorlib.transport_hid import HidTransport
