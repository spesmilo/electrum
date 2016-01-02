from ..trezor.client import trezor_client_class
from ..trezor.plugin import TrezorCompatiblePlugin, TrezorCompatibleWallet


class TrezorWallet(TrezorCompatibleWallet):
    wallet_type = 'trezor'
    device = 'Trezor'


class TrezorPlugin(TrezorCompatiblePlugin):
    firmware_URL = 'https://www.mytrezor.com'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    minimum_firmware = (1, 2, 1)
    wallet_class = TrezorWallet
    try:
        from trezorlib.client import proto, BaseClient, ProtocolMixin
        client_class = trezor_client_class(ProtocolMixin, BaseClient, proto)
        import trezorlib.ckd_public as ckd_public
        from trezorlib.client import types
        from trezorlib.transport_hid import HidTransport
        libraries_available = True
    except ImportError:
        libraries_available = False
