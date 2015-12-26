from electrum_ltc.wallet import BIP32_Hardware_Wallet

from plugins.trezor.gui_mixin import GuiMixin
from plugins.trezor.plugin_generic import TrezorCompatiblePlugin

try:
    from trezorlib.client import proto, BaseClient, ProtocolMixin
    from trezorlib.transport import ConnectionError
    from trezorlib.transport_hid import HidTransport
    TREZOR = True
except ImportError:
    TREZOR = False


class TrezorWallet(BIP32_Hardware_Wallet):
    wallet_type = 'trezor'
    root_derivation = "m/44'/2'"
    device = 'Trezor'

class TrezorPlugin(TrezorCompatiblePlugin):
    wallet_type = 'trezor'
    import trezorlib.ckd_public as ckd_public
    from trezorlib.client import types

    @staticmethod
    def libraries_available():
        return TREZOR

    def constructor(self, s):
        return TrezorWallet(s)

    def get_client(self):
        if not TREZOR:
            self.give_error('please install github.com/trezor/python-trezor')

        if not self.client or self.client.bad:
            d = HidTransport.enumerate()
            if not d:
                self.give_error('Could not connect to your Trezor. Please verify the cable is connected and that no other app is using it.')
            self.transport = HidTransport(d[0])
            self.client = QtGuiTrezorClient(self.transport)
            self.client.handler = self.handler
            self.client.set_tx_api(self)
            self.client.bad = False
            if not self.atleast_version(1, 2, 1):
                self.client = None
                self.give_error('Outdated Trezor firmware. Please update the firmware from https://www.mytrezor.com')
        return self.client

if TREZOR:
    class QtGuiTrezorClient(ProtocolMixin, GuiMixin, BaseClient):
        protocol = proto
        device = 'Trezor'

        def call_raw(self, msg):
            try:
                resp = BaseClient.call_raw(self, msg)
            except ConnectionError:
                self.bad = True
                raise

            return resp
