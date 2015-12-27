from electrum.wallet import BIP32_Hardware_Wallet

from plugins.trezor.client import trezor_client_class
from plugins.trezor.plugin import TrezorCompatiblePlugin

try:
    from trezorlib.client import proto, BaseClient, ProtocolMixin
    TREZOR = True
except ImportError:
    TREZOR = False


class TrezorWallet(BIP32_Hardware_Wallet):
    wallet_type = 'trezor'
    root_derivation = "m/44'/0'"
    device = 'Trezor'


class TrezorPlugin(TrezorCompatiblePlugin):
    client_class = trezor_client_class(ProtocolMixin, BaseClient, proto)
    firmware_URL = 'https://www.mytrezor.com'
    libraries_URL = 'https://github.com/trezor/python-trezor'
    libraries_available = TREZOR
    minimum_firmware = (1, 2, 1)
    wallet_class = TrezorWallet
    import trezorlib.ckd_public as ckd_public
    from trezorlib.client import types
    from trezorlib.transport_hid import HidTransport
