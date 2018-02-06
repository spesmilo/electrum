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
            import trezorlib.messages
            import trezorlib.device
            self.client_class = client.TrezorClient
            self.ckd_public = trezorlib.ckd_public
            self.types = trezorlib.messages
            self.DEVICE_IDS = ('TREZOR',)
            self.libraries_available = True
        except ImportError:
            self.libraries_available = False
        TrezorCompatiblePlugin.__init__(self, *args)

    def enumerate(self):
        from trezorlib.device import TrezorDevice
        from electrum.plugins import Device
        return [Device(str(d), -1, str(d), 'TREZOR', 0) for d in TrezorDevice.enumerate()]

    def transport(self, device):
        from trezorlib.device import TrezorDevice
        return TrezorDevice.find_by_path(device.path)
