import types
from unittest import mock

from electrum.hw_wallet.plugin import HW_PluginBase
from electrum.plugin import DeviceMgr
from electrum.simple_config import SimpleConfig

from .. import ElectrumTestCase


class FakeHwKeystore:
    def __init__(self):
        self.thread = mock.Mock()

    def pairing_code(self):
        return "fake_pairing_code"


class TestHwWalletCleanUp(ElectrumTestCase):
    """On wallet close, the hw keystore TaskThread must always get stopped.
    A still-running QThread at interpreter shutdown makes Qt abort() the process
    ("QThread: Destroyed while thread is still running").
    """

    def test_close_wallet_stops_keystore_thread_even_if_unpairing_fails(self):
        # unpairing does device I/O and can raise, e.g. BridgeException
        # "device not found" if the device was unplugged while the wallet was open
        devmgr = mock.Mock()
        devmgr.unpair_pairing_code.side_effect = Exception("trezord: acquire failed: device not found")
        plugin = types.SimpleNamespace(
            keystore_class=FakeHwKeystore,
            device_manager=lambda: devmgr,
        )
        keystore = FakeHwKeystore()
        wallet = mock.Mock()
        wallet.get_keystores.return_value = [keystore]
        try:
            HW_PluginBase.close_wallet(plugin, wallet)
        except Exception:
            pass  # run_hook() swallows exceptions raised by hooks
        keystore.thread.stop.assert_called_once()

    def test_unpair_pairing_code_tolerates_client_close_failing(self):
        config = SimpleConfig({'electrum_path': self.electrum_path})
        devmgr = DeviceMgr(config=config)
        client = mock.Mock()
        client.close.side_effect = Exception("trezord: acquire failed: device not found")
        devmgr.clients[client] = "hid_id_1"
        devmgr.pairing_code_to_id["pairing_code_1"] = "hid_id_1"
        devmgr.unpair_pairing_code("pairing_code_1")  # must not raise
        client.close.assert_called_once()
        self.assertNotIn(client, devmgr.clients)
        self.assertNotIn("pairing_code_1", devmgr.pairing_code_to_id)
