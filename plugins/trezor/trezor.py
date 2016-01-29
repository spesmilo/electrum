from .plugin import TrezorCompatiblePlugin, TrezorCompatibleWallet


class TrezorWallet(TrezorCompatibleWallet):
    wallet_type = 'trezor'
    device = 'TREZOR'


class TrezorPlugin(TrezorCompatiblePlugin):
    firmware_URL = 'https://www.mytrezor.com'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    minimum_firmware = (1, 2, 1)
    wallet_class = TrezorWallet
    try:
        from .client import TrezorClient as client_class
        import trezorlib.ckd_public as ckd_public
        from trezorlib.client import types
        from trezorlib.transport_hid import HidTransport, DEVICE_IDS
        libraries_available = True
    except ImportError:
        libraries_available = False
