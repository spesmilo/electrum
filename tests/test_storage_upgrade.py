import shutil
import tempfile
import os
import json
from typing import Optional
import asyncio
import inspect

import electrum
from electrum.wallet_db import WalletDBUpgrader, WalletDB, WalletRequiresUpgrade, WalletRequiresSplit
from electrum.bolt11 import BOLT11DecodeException
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

    @as_testnet
    async def test_upgrade_removes_invoice_with_malformed_route_tag(self):
        # Db conversion 72->73 drops stored invoices that fail bolt11 decoding.
        # Older versions decoded a malformed 'r'/'t' tag by silently skipping it, so such an
        # invoice can be sitting in a wallet file; without this conversion it would now abort
        # the load in Invoice._validate_invoice_str, leaving the file unopenable.
        # The older conversions that decode invoices themselves (45, 47, 51) drop such items
        # the same way, so a file from before those versions upgrades too.
        # The malformed invoices below are correctly signed, but their 'r'/'t' payload has
        # non-zero padding bits; see TestBolt11._encode_invoice_with_raw_tag.
        bad_r = ('lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq8w3jhxaqrqzq'
                 'pxhlj48td8uen6qqvke0kwsx0uf3g9pqfg3sdetumr2lla597ahcjcqcn5v7yycysc39ua9r2l8qx527'
                 'uthxfdgmhp47exeh98pv7facqmjed87')
        bad_t = ('lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq8w3jhxaqtqzq'
                 'pg3tvdu05w4rd9ccwjq80f5ujz89c5ltq5fhp8dqxg7aan38gs24z0pgx8xj4vvzt2su5fqpr35tz692'
                 'czrwt6e56twh3v8l0t8hfkxsq5xtyfu')
        good = ('lntb15u1p0m6lzupp5zqjthgvaad9mewmdjuehwddyze9d8zyxcc43zhaddeegt37sndgsdq4xysyymr0vd'
                '4kzcmrd9hx7cqp7xqrrss9qy9qsqsp5vlhcs24hwm747w8f3uau2tlrdkvjaglffnsstwyamj84cxuhrn2'
                's8tut3jqumepu42azyyjpgqa4w9w03204zp9h4clk499y2umstl6s29hqyj8vv4as6zt5567ux7l3f66m8'
                'pjhk65zjaq2esezk7ll2kcpljewkg')

        def invoice_json(lightning_invoice):
            return {'amount_msat': None, 'message': 'mymsg', 'time': 1615922274, 'exp': 0,
                    'outputs': None, 'height': 0, 'bip70': None,
                    'lightning_invoice': lightning_invoice}

        data = {
            'seed_version': 72,
            'wallet_type': 'imported',
            'addresses': {'tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385': {}},
            'invoices': {'bad_r': invoice_json(bad_r),
                         'bad_t': invoice_json(bad_t),
                         'good': invoice_json(good)},
        }
        db = self._load_db_from_json_string(wallet_json=json.dumps(data), upgrade=True)
        self.assertEqual(73, db.get('seed_version'))
        self.assertEqual(['good'], list(db.get_dict('invoices').keys()))

        # sanity: without the conversion (i.e. already at seed_version 73) the same file
        # would not load at all
        data['seed_version'] = 73
        with self.assertRaises(BOLT11DecodeException):
            self._load_db_from_json_string(wallet_json=json.dumps(data), upgrade=True)

        # a pre-45 file: conversion 45 decodes the invoices itself and drops the bad ones
        data['seed_version'] = 44
        data['invoices'] = {key: {'type': 2, 'invoice': invoice_str}
                            for key, invoice_str in (('bad_r', bad_r), ('bad_t', bad_t), ('good', good))}
        db = self._load_db_from_json_string(wallet_json=json.dumps(data), upgrade=True)
        self.assertEqual(73, db.get('seed_version'))
        self.assertEqual(['good'], list(db.get_dict('invoices').keys()))

    @as_testnet
    async def test_upgrade_removes_request_with_malformed_route_tag(self):
        # Same as the above, for the receive side: conversions 45, 47 and 51 each decode the
        # bolt11 str of stored payment_requests, and drop the ones that no longer decode.
        # (73 does not have to: a modern Request only stores the payment_hash.)
        bad_r = ('lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq8w3jhxaqrqzq'
                 'pxhlj48td8uen6qqvke0kwsx0uf3g9pqfg3sdetumr2lla597ahcjcqcn5v7yycysc39ua9r2l8qx527'
                 'uthxfdgmhp47exeh98pv7facqmjed87')
        good = ('lntb15u1p0m6lzupp5zqjthgvaad9mewmdjuehwddyze9d8zyxcc43zhaddeegt37sndgsdq4xysyymr0vd'
                '4kzcmrd9hx7cqp7xqrrss9qy9qsqsp5vlhcs24hwm747w8f3uau2tlrdkvjaglffnsstwyamj84cxuhrn2'
                's8tut3jqumepu42azyyjpgqa4w9w03204zp9h4clk499y2umstl6s29hqyj8vv4as6zt5567ux7l3f66m8'
                'pjhk65zjaq2esezk7ll2kcpljewkg')
        good_rhash = '1024bba19deb4bbcbb6d97337735a4164ad38886c62b115fad6e7285c7d09b51'

        def request_json(seed_version, lightning_invoice):
            """A payment_requests item holding a bolt11 str, in that seed_version's shape."""
            if seed_version < 45:
                return {'type': 2, 'invoice': lightning_invoice}
            # note: amount_msat must match the invoice and be an int, else conversion 54 drops it
            return {'amount_msat': 1_500_000, 'message': 'mymsg', 'time': 1615922274, 'exp': 0,
                    'outputs': None, 'height': 0, 'bip70': None,
                    'lightning_invoice': lightning_invoice}

        # 44 -> conversion 45 drops it, 46 -> conversion 47 does, 50 -> conversion 51 does
        for seed_version in (44, 46, 50):
            with self.subTest(seed_version=seed_version):
                data = {
                    'seed_version': seed_version,
                    'wallet_type': 'imported',
                    'addresses': {'tb1qmjzmg8nd4z56ar4fpngzsr6euktrhnjg9td385': {}},
                    'payment_requests': {'bad_r': request_json(seed_version, bad_r),
                                         good_rhash: request_json(seed_version, good)},
                }
                db = self._load_db_from_json_string(wallet_json=json.dumps(data), upgrade=True)
                self.assertEqual(73, db.get('seed_version'))
                self.assertEqual([good_rhash], list(db.get_dict('payment_requests').keys()))


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
