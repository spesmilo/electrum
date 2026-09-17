from typing import Tuple

from electrum import keystore
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.bip32 import BIP32Node
from electrum.bitcoin import address_to_script
from electrum.cosigner import (Cosigner, HIGH_DERIVATION_INDEX, add_cosigner,
                              check_cosigners_password)
from electrum.fee_policy import FixedFeePolicy
from electrum.simple_config import SimpleConfig
from electrum.transaction import PartialTransaction, PartialTxOutput, Transaction, tx_from_any
from electrum.util import InvalidPassword

from . import ElectrumTestCase
from .test_wallet_vertical import WalletIntegrityHelper


def _keys(name: str, xtype: str) -> Tuple[str, str]:
    """A master key pair of that type, the same one for a given name."""
    node = BIP32Node.from_rootseed(name.encode('utf8'), xtype=xtype)
    return node.to_xprv(), node.to_xpub()


class CosignerTestCase(ElectrumTestCase):
    """This device signs for wallets it does not have, see electrum/cosigner.py."""

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def _make_tx(self, wallet) -> PartialTransaction:
        """A transaction of that wallet, signed with the keys it has, as the cosigner
        gets it: through a QR code, so it carries nothing but what a PSBT carries.
        """
        spk = address_to_script(wallet.get_receiving_addresses()[0])
        funding_tx = Transaction(
            '0200000001' + 32 * '11' + '0000000000ffffffff01'
            + (100_000).to_bytes(8, 'little').hex() + bytes([len(spk)]).hex() + spk.hex() + '00000000')
        wallet.adb.receive_tx_callback(funding_tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        outputs = [PartialTxOutput.from_address_and_value('bc1qs2svwhfz47qv9qju2waa6prxzv5f522fc4p06t', 50_000)]
        tx = wallet.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(1000))
        wallet.sign_transaction(tx, password=None)  # does nothing if the wallet is watching-only
        qr_data, __ = tx.to_qr_data()
        return tx_from_any(qr_data)

    async def test_cosigns_for_a_multisig_wallet(self):
        # a 2-of-3 wallet on another device, which holds the first key only
        xprv1, xpub1 = _keys('key 1', 'p2wsh')
        xprv2, xpub2 = _keys('key 2', 'p2wsh')
        xprv3, xpub3 = _keys('key 3', 'p2wsh')
        wallet = WalletIntegrityHelper.create_multisig_wallet(
            [keystore.from_xprv(xprv1), keystore.from_xpub(xpub2), keystore.from_xpub(xpub3)],
            '2of3', config=self.config)
        tx = self._make_tx(wallet)
        self.assertFalse(tx.is_complete())

        cosigner = Cosigner(xprv=xprv2, xpubs=[xpub1, xpub3], m=2)
        # the change of the transaction is recomputed from the master public keys
        change = [txout for txout in tx.outputs() if cosigner.is_wallet_output(txout)]
        self.assertEqual(1, len(change))
        self.assertTrue(wallet.is_mine(change[0].address))

        cosigner.sign_transaction(tx)
        self.assertTrue(tx.is_complete())

    async def test_signs_for_a_single_sig_wallet(self):
        # a watching-only wallet on another device: this one holds its key
        xprv, xpub = _keys('the only key', 'p2wpkh')
        wallet = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub(xpub), config=self.config)
        tx = self._make_tx(wallet)
        self.assertFalse(tx.is_complete())

        cosigner = Cosigner(xprv=xprv)
        change = [txout for txout in tx.outputs() if cosigner.is_wallet_output(txout)]
        self.assertEqual(1, len(change))
        self.assertTrue(wallet.is_mine(change[0].address))

        cosigner.sign_transaction(tx)
        self.assertTrue(tx.is_complete())

    async def test_change_sent_far_ahead_of_the_wallet_is_flagged(self):
        # a wallet derives only a few addresses beyond the ones it has used, so change
        # sent far ahead of them may never be found: the app warns about that
        xprv, xpub = _keys('the only key', 'p2wpkh')
        wallet = WalletIntegrityHelper.create_standard_wallet(
            keystore.from_xpub(xpub), config=self.config)
        tx = self._make_tx(wallet)
        cosigner = Cosigner(xprv=xprv)

        change = [txout for txout in tx.outputs() if cosigner.is_wallet_output(txout)]
        self.assertEqual(1, len(change))
        self.assertFalse(cosigner.is_high_derivation_index(change[0]))

        # the transaction can pay to the wallet and still be out of its reach
        der_suffix = [1, HIGH_DERIVATION_INDEX]
        far_ahead = PartialTxOutput(
            scriptpubkey=cosigner.get_script_descriptor(der_suffix).expand().output_script,
            value=change[0].value)
        far_ahead.bip32_paths = {
            cosigner.keystore.derive_pubkey(*der_suffix): (bytes.fromhex(cosigner.cosigner_id), der_suffix)}
        self.assertTrue(cosigner.is_wallet_output(far_ahead))
        self.assertTrue(cosigner.is_high_derivation_index(far_ahead))

    async def test_script_type_follows_the_master_keys(self):
        for xtype, n, script_type in [
            ('standard', 1, 'p2pkh'),
            ('p2wpkh', 1, 'p2wpkh'),
            ('p2wpkh-p2sh', 1, 'p2wpkh-p2sh'),
            ('standard', 3, 'p2sh'),
            ('p2wsh', 3, 'p2wsh'),
            ('p2wsh-p2sh', 3, 'p2wsh-p2sh'),
        ]:
            with self.subTest(msg=f'{xtype} {n} of {n}'):
                keys = [_keys(f'key {i} {xtype}', xtype) for i in range(n)]
                cosigner = Cosigner(xprv=keys[0][0], xpubs=[xpub for __, xpub in keys[1:]], m=n)
                self.assertEqual(script_type, cosigner.script_type)

    async def test_qr_code_of_a_cosigner(self):
        xprv, xpub = _keys('ours', 'p2wsh')
        __, other = _keys('theirs', 'p2wsh')
        cosigner = Cosigner(xprv=xprv, xpubs=[other], m=2)
        self.assertEqual(f'cosigner:2:{xprv}:{other}', cosigner.to_qr_data())

        scanned = Cosigner.from_qr_data(cosigner.to_qr_data())
        self.assertEqual(cosigner.to_dict(), scanned.to_dict())
        # a cosigner is indexed by the fingerprint its key uses in transactions
        self.assertEqual(keystore.from_xpub(xpub).get_root_fingerprint(), scanned.cosigner_id)

    async def test_keys_that_use_two_passwords_cannot_all_be_read(self):
        # why the app must not let the user choose a new password once it holds keys:
        # they are read with a single password, which the daemon re-encrypts them with
        xprv_one, __ = _keys('one', 'p2wpkh')
        xprv_two, __ = _keys('two', 'p2wpkh')
        add_cosigner(self.config, Cosigner(xprv=xprv_one), 'password one')
        add_cosigner(self.config, Cosigner(xprv=xprv_two), 'password two')
        for password in ['password one', 'password two']:
            with self.assertRaises(InvalidPassword):
                check_cosigners_password(self.config, password)

    async def test_invalid_qr_codes(self):
        xprv, xpub = _keys('ours', 'p2wsh')
        __, other = _keys('theirs', 'p2wsh')
        __, single = _keys('theirs', 'p2wpkh')
        for data in [
            xprv,  # not a cosigner QR code at all
            f'cosigner:2:{xpub}:{other}',  # a public key cannot sign
            f'cosigner:2:{xprv}:{other}:{other}',  # the same key twice
            f'cosigner:3:{xprv}:{other}',  # more signatures than keys
            f'cosigner:0:{xprv}',  # no signature at all
            f'cosigner:1:{xprv}:{single}',  # keys of different types
        ]:
            with self.assertRaises(ValueError):
                Cosigner.from_qr_data(data)
