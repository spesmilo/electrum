import shutil
import tempfile
import os
import json
from typing import Optional
import asyncio
import inspect

import electrum
from electrum.wallet_db import WalletDBUpgrader, WalletDB, WalletRequiresUpgrade, WalletRequiresSplit
from electrum.wallet import Wallet
from electrum import constants
from electrum import util
from electrum.plugin import Plugins
from electrum.simple_config import SimpleConfig

from . import as_testnet, as_regtest
from .test_wallet import WalletTestCase




# TODO add other wallet types: 2fa, xpub-only
# TODO hw wallet with client version 2.6.x (single-, and multiacc)
class TestStorageUpgrade(WalletTestCase):

    def _get_wallet_str(self):
        test_method_name = inspect.stack()[1][3]
        assert isinstance(test_method_name, str)
        assert test_method_name.startswith("test_upgrade_from_")
        fname = test_method_name[len("test_upgrade_from_"):]
        test_vector_file = self.get_wallet_file_path(fname)
        with open(test_vector_file, "r") as f:
            wallet_str = f.read()
        return wallet_str


##########

    async def test_upgrade_from_client_1_9_8_seeded(self):
        """note: this wallet file is not valid json: it tests the ast.literal_eval()
        fallback in wallet_db.load_data()
        """
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    # TODO pre-2.0 mixed wallets are not split currently
    #async def test_upgrade_from_client_1_9_8_mixed(self):
    #    wallet_str = "{'addr_history':{'15V7MsQK2vjF5aEXLVG11qi2eZPZsXdnYc':[],'177hEYTccmuYH8u68pYfaLteTxwJrVgvJj':[],'1DjtUCcQwwzA3GSPA7Kd79PMnri7tLDPYC':[],'1PGEgaPG1XJqmuSj68GouotWeYkCtwo4wm':[],'1PAgpPxnL42Hp3cWxmSfdChPqqGiM8g7zj':[],'1DgrwN2JCDZ6uPMSvSz8dPeUtaxLxWM2kf':[],'1H3mPXHFzA8UbvhQVabcDjYw3CPb3djvxs':[],'1HocPduHmQUJerpdaLG8DnmxvnDCVQwWsa':[]},'accounts_expanded':{},'master_public_key':'756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb','use_encryption':False,'seed':'2605aafe50a45bdf2eb155302437e678','accounts':{0:{0:['1DjtUCcQwwzA3GSPA7Kd79PMnri7tLDPYC','1PAgpPxnL42Hp3cWxmSfdChPqqGiM8g7zj','177hEYTccmuYH8u68pYfaLteTxwJrVgvJj','1PGEgaPG1XJqmuSj68GouotWeYkCtwo4wm','15V7MsQK2vjF5aEXLVG11qi2eZPZsXdnYc'],1:['1H3mPXHFzA8UbvhQVabcDjYw3CPb3djvxs','1HocPduHmQUJerpdaLG8DnmxvnDCVQwWsa','1DgrwN2JCDZ6uPMSvSz8dPeUtaxLxWM2kf'],'mpk':'756d1fe6ded28d43d4fea902a9695feb785447514d6e6c3bdf369f7c3432fdde4409e4efbffbcf10084d57c5a98d1f34d20ac1f133bdb64fa02abf4f7bde1dfb'}},'imported_keys':{'15CyDgLffJsJgQrhcyooFH4gnVDG82pUrA':'5JyVyXU1LiRXATvRTQvR9Kp8Rx1X84j2x49iGkjSsXipydtByUq','1Exet2BhHsFxKTwhnfdsBMkPYLGvobxuW6':'L3Gi6EQLvYw8gEEUckmqawkevfj9s8hxoQDFveQJGZHTfyWnbk1U','1364Js2VG66BwRdkaoxAaFtdPb1eQgn8Dr':'L2sED74axVXC4H8szBJ4rQJrkfem7UMc6usLCPUoEWxDCFGUaGUM'},'seed_version':4}"
    #    await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_0_4_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_0_4_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_0_4_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_1_1_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_1_1_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_2_0_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_2_0_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_3_2_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_3_2_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_4_3_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_4_3_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_5_4_trezor_multiacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str, accounts=2)

    async def test_upgrade_from_client_2_5_4_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_6_4_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_7_18_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    # seed_version 13 is ambiguous
    # client 2.7.18 created wallets with an earlier "v13" structure
    # client 2.8.3 created wallets with a later "v13" structure
    # client 2.8.3 did not do a proper clean-slate upgrade
    # the wallet here was created in 2.7.18 with a couple privkeys imported
    # then opened in 2.8.3, after which a few other new privkeys were imported
    # it's in some sense in an "inconsistent" state
    async def test_upgrade_from_client_2_8_3_importedkeys_flawed_previous_upgrade_from_2_7_18(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_8_3_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_seeded(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    @as_testnet
    async def test_upgrade_from_client_2_9_3_old_seeded_with_realistic_history(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_importedkeys(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_watchaddresses(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_trezor_singleacc(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_2_9_3_multisig(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_3_2_3_ledger_standard_keystore_changes(self):
        # see #6066
        wallet_str = self._get_wallet_str()
        db = await self._upgrade_storage(wallet_str)
        wallet = Wallet(db, config=self.config)
        ks = wallet.keystore
        # to simulate ks.opportunistically_fill_in_missing_info_from_device():
        ks._root_fingerprint = "deadbeef"
        ks.is_requesting_to_be_rewritten_to_wallet_file = True
        await wallet.stop()

    async def test_upgrade_from_client_2_9_3_importedkeys_keystore_changes(self):
        # see #6401
        wallet_str = self._get_wallet_str()
        db = await self._upgrade_storage(wallet_str)
        wallet = Wallet(db, config=self.config)
        wallet.import_private_keys(
            ["p2wpkh:L1cgMEnShp73r9iCukoPE3MogLeueNYRD9JVsfT1zVHyPBR3KqBY"],
            password=None
        )
        await wallet.stop()

    @as_testnet
    async def test_upgrade_from_client_3_3_8_xpub_with_realistic_history(self):
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    async def test_upgrade_from_client_4_0_1_with_invoices(self):
        # wallet with one invoice and one request. seed_version is 31
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    @as_testnet
    async def test_upgrade_from_client_4_5_2_9dk_with_ln(self):
        # This is a realistic testnet wallet, from the "9dk" seed, including some lightning sends/receives,
        # some labels, frozen addresses, saved local txs, invoices/requests, etc. The file also has partial writes.
        # Also, regression test for #8913
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    @as_regtest
    async def test_upgrade_from_client_4_6_0_with_unfulfilled_htlcs(self):
        # tests unfulfilled_htlcs conversion in 62->63. seed_version is 60.
        wallet_str = self._get_wallet_str()
        await self._upgrade_storage(wallet_str)

    @as_testnet
    async def test_upgrade_from_client_4_8_1_9dk_with_ln_chan_backups(self):
        # Has LN "imported_channel_backups" and "onchain_channel_backups".
        # This tests imported chan backup conversion (db version 71->72).
        wallet_str = self._get_wallet_str()
        db = await self._upgrade_storage(wallet_str)
        assert db.get("imported_channel_backups").get("ddb06b023f24a587d96a9f113c02d266549d010a57d7b151c1f5332a9bbaafd5") \
            == "0200017e634853dc47f0bc2f2e0d1054b302fcb414371ddbd889f29ba8aa4e8b62c7725d472c7b642b14176f275d6dca60c8d1ec5cfbf935169f1fe873e6bd0ad155da038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9d5afba9b2a33f5c151b1d7570a019d5466d2023c119f6ad987a5243f026bb0dd00003e74623171357a64726430703772366d68353961726e636179763030326e727530347030706636653264756b6479326833707672726e67747336687473616a02f2fa10e1317153b9cca5c0af211bcdd48aac4cf67a6f4d1cb7de71857261a1190303a53b5175b7ad2de558fc1f140d129fc5dd0949f1fbfac28ce2c33b236fbc6ef00390000e3230332e3133322e39342e313936072602a1ceaaae7b1da9d2e679977615988c62903e93a2e5d972aff6f0441face4be10c87b61e091f3f786ca44dc25283557214686d5ddb138eeb9df484145b991356b"


##########

    plugins: 'electrum.plugin.Plugins'

    def setUp(self):
        super().setUp()
        gui_name = 'cmdline'
        # TODO it's probably wasteful to load all plugins... only need Trezor
        self.plugins = Plugins(self.config, gui_name)

    def tearDown(self):
        self.plugins.stop()
        self.plugins.stopped_event.wait()
        super().tearDown()

    async def _upgrade_storage(self, wallet_json, accounts=1) -> Optional[WalletDB]:
        if accounts == 1:
            # test manual upgrades
            try:
                db = self._load_db_from_json_string(
                    wallet_json=wallet_json,
                    upgrade=False)
            except WalletRequiresUpgrade:
                db = self._load_db_from_json_string(
                    wallet_json=wallet_json,
                    upgrade=True)
                await self._sanity_check_upgraded_db(db)
            return db
        else:
            try:
                db = self._load_db_from_json_string(
                    wallet_json=wallet_json,
                    upgrade=False)
            except WalletRequiresSplit as e:
                split_data = e._split_data
                self.assertEqual(accounts, len(split_data))
                for item in split_data:
                    data = json.dumps(item)
                    new_db = WalletDB(data, storage=None, upgrade=True)
                    await self._sanity_check_upgraded_db(new_db)

    async def _sanity_check_upgraded_db(self, db):
        wallet = Wallet(db, config=self.config)
        await wallet.stop()

    @staticmethod
    def _load_db_from_json_string(*, wallet_json, upgrade):
        db = WalletDB(wallet_json, storage=None, upgrade=upgrade)
        return db
