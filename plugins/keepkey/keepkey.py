from electrum.wallet import BIP32_Hardware_Wallet

from plugins.trezor.gui_mixin import GuiMixin
from plugins.trezor.plugin_generic import TrezorCompatiblePlugin

try:
    from keepkeylib.client import proto, BaseClient, ProtocolMixin
    KEEPKEY = True
except ImportError:
    KEEPKEY = False


class KeepKeyWallet(BIP32_Hardware_Wallet):
    wallet_type = 'keepkey'
    root_derivation = "m/44'/0'"
    device = 'KeepKey'


class KeepKeyPlugin(TrezorCompatiblePlugin):
    client_class = trezor_client_class(ProtocolMixin, BaseClient, proto)
    firmware_URL = 'https://www.keepkey.com'
    libraries_URL = 'https://github.com/keepkey/python-keepkey'
    libraries_available = KEEPKEY
    minimum_firmware = (1, 0, 0)
    wallet_class = KeepKeyWallet
    import keepkeylib.ckd_public as ckd_public
    from keepkeylib.client import types
    from keepkeylib.transport_hid import HidTransport
