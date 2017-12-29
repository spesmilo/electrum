from .plugin import TrezorCompatiblePlugin, TrezorCompatibleKeyStore


class TrezorKeyStore(TrezorCompatibleKeyStore):
    hw_type = 'trezor'
    device = 'TREZOR'

class TrezorPlugin(TrezorCompatiblePlugin):
    firmware_URL = 'https://wallet.trezor.io'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    minimum_firmware = (1, 5, 2)
    keystore_class = TrezorKeyStore

    def __init__(self, *args):
        try:
            from . import client
            import trezorlib
            import trezorlib.ckd_public
            import trezorlib.transport_hid
            import trezorlib.messages
            self.client_class = client.TrezorClient
            self.ckd_public = trezorlib.ckd_public
            self.types = trezorlib.messages
            self.DEVICE_IDS = (trezorlib.transport_hid.DEV_TREZOR1, trezorlib.transport_hid.DEV_TREZOR2)
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False
        TrezorCompatiblePlugin.__init__(self, *args)

    def hid_transport(self, device):
        from trezorlib.transport_hid import HidTransport
        return HidTransport.find_by_path(device.path)

    def bridge_transport(self, d):
        from trezorlib.transport_bridge import BridgeTransport
        return BridgeTransport(d)
