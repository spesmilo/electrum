from .plugin import TrezorCompatiblePlugin, TrezorCompatibleKeyStore


class TrezorKeyStore(TrezorCompatibleKeyStore):
    hw_type = 'trezor'
    device = 'TREZOR'

class TrezorPlugin(TrezorCompatiblePlugin):
    firmware_URL = 'https://www.mytrezor.com'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    minimum_firmware = (1, 3, 3)
    keystore_class = TrezorKeyStore

    def __init__(self, *args):
        try:
            import client
            import trezorlib
            import trezorlib.ckd_public
            import trezorlib.transport_hid
            self.client_class = client.TrezorClient
            self.ckd_public = trezorlib.ckd_public
            self.types = trezorlib.client.types
            self.DEVICE_IDS = trezorlib.transport_hid.DEVICE_IDS
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False
        TrezorCompatiblePlugin.__init__(self, *args)

    def hid_transport(self, pair):
        from trezorlib.transport_hid import HidTransport
        return HidTransport(pair)

    def bridge_transport(self, d):
        from trezorlib.transport_bridge import BridgeTransport
        return BridgeTransport(d)
