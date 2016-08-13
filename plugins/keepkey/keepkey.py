from ..trezor.plugin import TrezorCompatiblePlugin, TrezorCompatibleKeyStore


class KeepKey_KeyStore(TrezorCompatibleKeyStore):
    wallet_type = 'keepkey'
    device = 'KeepKey'


class KeepKeyPlugin(TrezorCompatiblePlugin):
    firmware_URL = 'https://www.keepkey.com'
    libraries_URL = 'https://github.com/keepkey/python-keepkey'
    minimum_firmware = (1, 0, 0)
    keystore_class = KeepKey_KeyStore
    try:
        from .client import KeepKeyClient as client_class
        import keepkeylib.ckd_public as ckd_public
        from keepkeylib.client import types
        from keepkeylib.transport_hid import HidTransport, DEVICE_IDS
        libraries_available = True
    except ImportError:
        libraries_available = False
