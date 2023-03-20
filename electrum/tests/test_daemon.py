import os

from electrum.daemon import Daemon
from electrum.simple_config import SimpleConfig
from electrum.wallet import restore_wallet_from_text, Abstract_Wallet, Standard_Wallet
from electrum import util

from . import ElectrumTestCase


class TestUnifiedPassword(ElectrumTestCase):
    config: 'SimpleConfig'

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.set_key("single_password", True)

        self.wallet_dir = os.path.dirname(self.config.get_wallet_path())
        assert "wallets" == os.path.basename(self.wallet_dir)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.daemon = Daemon(config=self.config, listen_jsonrpc=False)

    async def asyncTearDown(self):
        await self.daemon.stop()
        await super().asyncTearDown()

    async def test_update_password_for_directory(self):
        wallet1: Standard_Wallet = restore_wallet_from_text(
            "9dk", path=f"{self.wallet_dir}/w1", password=None, gap_limit=2, config=self.config)['wallet']
        wallet2: Standard_Wallet = restore_wallet_from_text(
            "x8", path=f"{self.wallet_dir}/w2", password="123456", gap_limit=2, config=self.config)['wallet']
        can_be_unified, is_unified = self.daemon._check_password_for_directory(old_password="123456", wallet_dir=self.wallet_dir)
        self.assertEqual((True, False), (can_be_unified, is_unified))
        is_unified = self.daemon.update_password_for_directory(old_password="123456", new_password="123456")
        self.assertTrue(is_unified)



