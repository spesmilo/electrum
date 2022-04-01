import json

from electrum.wallet_db import WalletDB, FINAL_SEED_VERSION

from . import SequentialTestCase


class WalletDBTestCase(SequentialTestCase):

    def test_check_unfinished_multisig(self):
        d = {'wallet_type': 'standard', "seed_version": FINAL_SEED_VERSION}

        db = WalletDB(json.dumps(d), manual_upgrades=False)
        assert not db.check_unfinished_multisig()

        d['wallet_type'] = '2of3'
        d['x1/'] = d['x2/'] = d['x3/'] = 'some data'
        db = WalletDB(json.dumps(d), manual_upgrades=False)
        assert not db.check_unfinished_multisig()

        del d['x3/']
        db = WalletDB(json.dumps(d), manual_upgrades=False)
        assert db.check_unfinished_multisig()  # x1/, x2/ pass
        assert db.check_unfinished_multisig()

        del d['x2/']
        db = WalletDB(json.dumps(d), manual_upgrades=False)
        assert db.check_unfinished_multisig()  # x1/ pass
        assert db.check_unfinished_multisig()

        del d['x1/']
        db = WalletDB(json.dumps(d), manual_upgrades=False)
        assert not db.check_unfinished_multisig()  # no x1/ fails

        d['x1/'] = d['x3/'] = 'some data'
        db = WalletDB(json.dumps(d), manual_upgrades=False)
        assert not db.check_unfinished_multisig()  # x1/, x3/ fails

        d['x2/'] = 'some data'
        del d['x1/']
        db = WalletDB(json.dumps(d), manual_upgrades=False)
        assert not db.check_unfinished_multisig()  # x2/, x3/ fails
