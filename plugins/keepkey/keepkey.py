from electrum_ltc.wallet import BIP32_Hardware_Wallet

from plugins.trezor.gui_mixin import GuiMixin
from plugins.trezor.plugin_generic import TrezorCompatiblePlugin

try:
    from keepkeylib.client import proto, BaseClient, ProtocolMixin
    from keepkeylib.transport import ConnectionError
    from keepkeylib.transport_hid import HidTransport
    KEEPKEY = True
except ImportError:
    KEEPKEY = False


class KeepKeyWallet(BIP32_Hardware_Wallet):
    wallet_type = 'keepkey'
    root_derivation = "m/44'/2'"
    device = 'KeepKey'


class KeepKeyPlugin(TrezorCompatiblePlugin):
    wallet_type = 'keepkey'
    import keepkeylib.ckd_public as ckd_public
    from keepkeylib.client import types

    @staticmethod
    def libraries_available():
        return KEEPKEY

    def constructor(self, s):
        return KeepKeyWallet(s)

    def get_client(self):
        if not KEEPKEY:
            give_error('please install github.com/keepkey/python-keepkey')

        if not self.client or self.client.bad:
            d = HidTransport.enumerate()
            if not d:
                give_error('Could not connect to your KeepKey. Please verify the cable is connected and that no other app is using it.')
            self.transport = HidTransport(d[0])
            self.client = QtGuiKeepKeyClient(self.transport)
            self.client.handler = self.handler
            self.client.set_tx_api(self)
            self.client.bad = False
            if not self.atleast_version(1, 0, 0):
                self.client = None
                give_error('Outdated KeepKey firmware. Please update the firmware from https://www.keepkey.com')
        return self.client


if KEEPKEY:
    class QtGuiKeepKeyClient(ProtocolMixin, GuiMixin, BaseClient):
        protocol = proto
        device = 'KeepKey'

        def call_raw(self, msg):
            try:
                resp = BaseClient.call_raw(self, msg)
            except ConnectionError:
                self.bad = True
                raise

            return resp
