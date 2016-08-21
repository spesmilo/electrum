from ..trezor.plugin import TrezorCompatiblePlugin, TrezorCompatibleKeyStore


class KeepKey_KeyStore(TrezorCompatibleKeyStore):
    hw_type = 'keepkey'
    device = 'KeepKey'


class KeepKeyPlugin(TrezorCompatiblePlugin):
    firmware_URL = 'https://www.keepkey.com'
    libraries_URL = 'https://github.com/keepkey/python-keepkey'
    minimum_firmware = (1, 0, 0)
    keystore_class = KeepKey_KeyStore

    def __init__(self, *args):
        try:
            import client
            import keepkeylib
            import keepkeylib.ckd_public
            import keepkeylib.transport_hid
            self.client_class = client.KeepKeyClient
            self.ckd_public = keepkeylib.ckd_public
            self.types = keepkeylib.client.types
            self.DEVICE_IDS = keepkeylib.transport_hid.DEVICE_IDS
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False
        TrezorCompatiblePlugin.__init__(self, *args)

    def hid_transport(self, pair):
        from keepkeylib.transport_hid import HidTransport
        return HidTransport(pair)

    def bridge_transport(self, d):
        raise NotImplementedError('')
