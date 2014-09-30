from PyQt4.Qt import QVBoxLayout
import PyQt4.QtCore as QtCore

import electrum
from electrum_gui.qt.util import ok_cancel_buttons2
from electrum_gui.qt import seed_dialog
from electrum.account import BIP32_Account
from electrum.bitcoin import hash_160_to_bc_address, hash_160, deserialize_xkey, CKD_pub, bip32_root, \
    bip32_private_derivation, int_to_hex, DecodeBase58Check
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.transaction import Transaction
from electrum.wallet import Wallet_2of3, Wallet
from electrum.account import BIP32_Account_2of3

from electrum.util import print_msg

try:
    import mnemonic
    loaded_mnemonic = True
except ImportError:
    loaded_mnemonic = False


MSG_ENTER_GAIT_MNEMONIC = _("Please enter your GreenAddress wallet mnemonic")
MSG_ENTER_GAIT_2OF3_MNEMONIC = _("Please enter your GreenAddress 2of3 subaccount mnemonic")
MSG_ENTER_GAIT_XPUB = _("Please enter your GreenAddress xpub key")


class Plugin(BasePlugin):

    def fullname(self):
        return 'GreenAddress 2of3 recovery'

    def description(self):
        return 'Provides support for GreenAddress 2of3 subaccounts recovery'

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = loaded_mnemonic
        self.wallet = None
        electrum.wallet.wallet_types.append(('multisig_recovery', 'ga_2of3_recovery', _("GreenAddress 2of3 recovery"), GA2of3RecoveryWallet))

    def is_available(self):
        if self.wallet is None:
            return True
        if self.wallet.storage.get('wallet_type') == 'ga_2of3_recovery':
            return True
        return False

    def set_enabled(self, enabled):
        self.wallet.storage.put('use_' + self.name, enabled)

    def is_enabled(self):
        if not self.is_available():
            return False

        if not self.wallet or self.wallet.storage.get('wallet_type') == 'ga_2of3_recovery':
            return True

        return self.wallet.storage.get('use_' + self.name) is True

    def enable(self):
        return BasePlugin.enable(self)

    @hook
    def load_wallet(self, wallet):
        self.wallet = wallet

    def is_gait_mnemonic(self, text):
        english = mnemonic.Mnemonic('english')
        return len(text.split(' ')) == 24 and english.check(text)

    def is_correct(self, mnemonic_gait, mnemonic_2of3, xpub_gait):
        return Wallet.is_xpub(xpub_gait) and self.is_gait_mnemonic(mnemonic_gait) and self.is_gait_mnemonic(mnemonic_2of3)

    def multi_seed_dialog(self, wizard):
        vbox = QVBoxLayout()
        vbox1, seed_e1 = seed_dialog.enter_seed_box(MSG_ENTER_GAIT_MNEMONIC, wizard, 'hot')
        vbox.addLayout(vbox1)
        vbox2, seed_e2 = seed_dialog.enter_seed_box(MSG_ENTER_GAIT_2OF3_MNEMONIC, wizard, 'hot')
        vbox.addLayout(vbox2)
        vbox3, seed_e3 = seed_dialog.enter_seed_box(MSG_ENTER_GAIT_XPUB, wizard, 'cold')
        vbox.addLayout(vbox3)
        entries = [seed_e1, seed_e2, seed_e3]

        vbox.addStretch(1)
        hbox, button = ok_cancel_buttons2(wizard, _('Next'))
        vbox.addLayout(hbox)
        button.setEnabled(False)

        f = lambda: button.setEnabled( self.is_correct(*map(wizard.get_seed_text, entries)) )
        for e in entries:
            e.textChanged.connect(f)

        wizard.set_layout(vbox)
        if not wizard.exec_():
            return
        return map(lambda e: wizard.get_seed_text(e), entries)

    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != 'ga_2of3_recovery':
            return

        r = self.multi_seed_dialog(wizard)
        if not r:
            return

        text1, text2, text3 = r
        wallet = GA2of3RecoveryWallet(storage)

        password = wizard.password_dialog()

        wallet.add_seed(text1, password)
        wallet.create_master_keys(password, text3)

        wallet.add_cosigner_seed(text2, "x2/", password, text3)

        wallet.add_master_public_key("x3/", text3)

        wallet.create_main_account(password)

        return wallet


class GA2of3RecoveryWallet(Wallet_2of3):
    wallet_type = 'ga_2of3_recovery'
    root_derivation = 'm/'

    def __init__(self, storage):
        Wallet_2of3.__init__(self, storage)

        # avoid issues with creating new addresses invisible in GreenAddress
        self.use_change = False

    def mnemonic_to_seed(self, seed, password):
        # Use standard BIP39 mnemonic instead of custom Electrum's
        return mnemonic.Mnemonic.to_seed(seed, password)

    def create_main_account(self, password):
        xpub1 = self.master_public_keys.get("x1/")
        xpub2 = self.master_public_keys.get("x2/")
        xpub3 = self.master_public_keys.get("x3/")
        account = GA2of3Account({'xpub':xpub1, 'xpub2':xpub2, 'xpub3':xpub3})
        self.add_account('0', account)

    def create_master_keys(self, password, xpub3):
        seed = self.get_seed(password)
        self.add_cosigner_seed(seed, self.root_name, password, xpub3)

    def add_cosigner_seed(self, seed, name, password, xpub3=None):
        # we don't store the seed, only the master xpriv
        xprv, xpub = bip32_root(self.mnemonic_to_seed(seed,''))

        if xpub3:
            deriv = self.root_derivation
            depth, fingerprint, child_number, c, K_or_k = deserialize_xkey(xpub3)
            child_number = int(child_number.encode('hex'), 16)
            deriv += "3'/" + str(child_number)+"'"
            xprv, xpub = bip32_private_derivation(xprv, "m/", deriv)
        elif self.root_derivation != 'm/':
            xprv, xpub = bip32_private_derivation(xprv, "m/", self.root_derivation)
        self.add_master_public_key(name, xpub)
        self.add_master_private_key(name, xprv, password)

    def load_accounts(self):
        self.accounts = {}

        d = self.storage.get('accounts', {})
        for k, v in d.items():
            if self.wallet_type == 'old' and k in [0, '0']:
                v['mpk'] = self.storage.get('master_public_key')
                self.accounts[k] = OldAccount(v)
            elif v.get('imported'):
                self.accounts[k] = ImportedAccount(v)
            elif v.get('xpub3') and v.get('gait_recovery'):
                self.accounts[k] = GA2of3Account(v)
            elif v.get('xpub3'):
                self.accounts[k] = BIP32_Account_2of3(v)
            elif v.get('xpub2'):
                self.accounts[k] = BIP32_Account_2of2(v)
            elif v.get('xpub'):
                self.accounts[k] = BIP32_Account(v)
            elif v.get('pending'):
                self.accounts[k] = PendingAccount(v)
            else:
                print_error("cannot load account", v)

    def get_account_addresses(self, a, include_change=True):
        # don't include change, otherwise it'd return duplicate addresses since
        # change=receiving for gait
        return Wallet_2of3.get_account_addresses(self, a, include_change=False)

    def add_input_info(self, txin):
        address = txin['address']
        account_id, sequence = self.get_address_index(address)
        account = self.accounts[account_id]
        redeemScript = account.redeem_script(*sequence)
        pubkeys = account.get_pubkeys(*sequence)
        x_pubkeys = account.get_xpubkeys(*sequence)
        # sort pubkeys and x_pubkeys, using the gait order
        pubkeys, x_pubkeys = ([pubkeys[2], pubkeys[0], pubkeys[1]],
                              [x_pubkeys[2], x_pubkeys[0], x_pubkeys[1]])
        txin['pubkeys'] = list(pubkeys)
        txin['x_pubkeys'] = list(x_pubkeys)
        txin['signatures'] = [None] * len(pubkeys)

        if redeemScript:
            txin['redeemScript'] = redeemScript
            txin['num_sig'] = 2
        else:
            txin['redeemPubkey'] = account.get_pubkey(*sequence)
            txin['num_sig'] = 1

class GA2of3Account(BIP32_Account_2of3):

    def pubkeys_to_address(self, pubkeys):
        redeem_script = Transaction.multisig_script([pubkeys[2], pubkeys[0], pubkeys[1]], 2)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return address

    def redeem_script(self, for_change, n):
        pubkeys = self.get_pubkeys(for_change, n)
        return Transaction.multisig_script([pubkeys[2], pubkeys[0], pubkeys[1]], 2)

    @classmethod
    def derive_pubkey_from_xpub(self, xpub, for_change, n, regular_branch):
        _, _, _, c, cK = deserialize_xkey(xpub)
        if regular_branch:
            cK, c = CKD_pub(cK, c, 1)
        cK, c = CKD_pub(cK, c, n)
        return cK.encode('hex')

    def get_xpubkeys(self, for_change, n):
        s = ''.join([int_to_hex(1,2), # REGULAR branch
                     int_to_hex(n+1,2)])
        xpubs = self.get_master_pubkeys()
        return map(lambda xpub: 'ff' + DecodeBase58Check(xpub).encode('hex') + s, xpubs)

    def derive_pubkeys(self, for_change, n):
        return map(lambda (i, x): self.derive_pubkey_from_xpub(x, for_change, n, regular_branch=(i!=2)),
                enumerate(self.get_master_pubkeys()))

    def create_new_address(self, for_change):
        n = len(self.pubkeys)+1
        pubkeys = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(pubkeys)
        self.pubkeys.append(pubkeys)
        self.receiving_addresses.append(address)
        self.change_addresses.append(address)
        print_msg(address)
        return address

    def __init__(self, v):
        self.pubkeys             = v.get('all', [])
        # addresses will not be stored on disk
        self.receiving_addresses = map(self.pubkeys_to_address, self.pubkeys)
        self.change_addresses    = map(self.pubkeys_to_address, self.pubkeys)
        self.xpub = v['xpub']
        self.xpub2 = v['xpub2']
        self.xpub3 = v['xpub3']

    def dump(self):
        return {'all': self.pubkeys, 'xpub': self.xpub, 'xpub2': self.xpub2, 'xpub3': self.xpub3,
                'gait_recovery': True}

    def get_pubkey(self, for_change, n):
        return self.pubkeys[n]
