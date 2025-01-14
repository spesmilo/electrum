from typing import TYPE_CHECKING, Optional

from electrum import bip32
from electrum.bip32 import BIP32Node, InvalidMasterKeyVersionBytes
from electrum.i18n import _
from electrum.plugin import Device, hook
from electrum.keystore import Hardware_KeyStore, KeyStoreWithMPK
from electrum.transaction import PartialTransaction
from electrum.wallet import Standard_Wallet, Multisig_Wallet, Abstract_Wallet
from electrum.util import bfh, bh2u, versiontuple, UserFacingException
from electrum.base_wizard import ScriptTypeNotSupported
from electrum.logging import get_logger

from ..hw_wallet import HW_PluginBase, HardwareClientBase
from ..hw_wallet.plugin import LibraryFoundButUnusable, only_hook_if_libraries_available


_logger = get_logger(__name__)

class CoboVault_KeyStore(Hardware_KeyStore):
    hw_type = 'cobovault'
    device = 'CoboVault'

    plugin: 'CoboVaultPlugin'

    def get_client(self):
        return self.plugin.get_client(self)

    def decrypt_message(self, pubkey, message, password):
        raise UserFacingException(_('Encryption and decryption are currently not supported for {}').format(self.device))

    def sign_message(self, sequence, message, password):
        # not support sign online for cobo vault
        raise UserFacingException(_('Sign message currently not supported for {}').format(self.device))

    def sign_transaction(self, tx, password):
        # not support sign online for cobo vault
        pass


class CoboVaultPlugin(HW_PluginBase):
    keystore_class = CoboVault_KeyStore
    minimum_library = (0, 0, 3)

    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        self.libraries_available = True

    @staticmethod
    def export_ms_wallet(wallet: Multisig_Wallet, fp, name):
        # export multi-sign wallet to txt file
        assert isinstance(wallet, Multisig_Wallet)

        print('# Exported from Electrum', file=fp)
        print(f'Name: {name:.20s}', file=fp)
        print(f'Policy: {wallet.m} of {wallet.n}', file=fp)
        print(f'Format: {wallet.txin_type.upper()}' , file=fp)

        xpubs = []
        derivs = set()
        for xpub, ks in zip(wallet.get_master_public_keys(), wallet.get_keystores()):  # type: str, KeyStoreWithMPK
            fp_bytes, der_full = ks.get_fp_and_derivation_to_be_used_in_partial_tx(der_suffix=[], only_der_suffix=False)
            fp_hex = fp_bytes.hex().upper()
            der_prefix_str = bip32.convert_bip32_intpath_to_strpath(der_full)
            xpubs.append( (fp_hex, xpub, der_prefix_str) )
            derivs.add(der_prefix_str)

        if len(derivs) == 1:
            print("Derivation: " + derivs.pop(), file=fp)

        print('', file=fp)

        assert len(xpubs) == wallet.n
        for xfp, xpub, der_prefix in xpubs:
            if derivs:
                print(f'# derivation: {der_prefix}', file=fp)

            print(f'{xfp}: {xpub}\n', file=fp)

