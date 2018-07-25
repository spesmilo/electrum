# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
import traceback
from functools import partial

from . import bitcoin
from . import keystore
from .keystore import bip44_derivation, purpose48_derivation
from .wallet import Imported_Wallet, Standard_Wallet, Multisig_Wallet, wallet_types, Wallet
from .storage import STO_EV_USER_PW, STO_EV_XPUB_PW, get_derivation_used_for_hw_device_encryption
from .i18n import _
from .util import UserCancelled, InvalidPassword, WalletFileException

# hardware device setup purpose
HWD_SETUP_NEW_WALLET, HWD_SETUP_DECRYPT_WALLET = range(0, 2)


class ScriptTypeNotSupported(Exception): pass


class GoBack(Exception): pass


class BaseWizard(object):

    def __init__(self, config, plugins, storage):
        super(BaseWizard, self).__init__()
        self.config = config
        self.plugins = plugins
        self.storage = storage
        self.wallet = None
        self.stack = []
        self.plugin = None
        self.keystores = []
        self.is_kivy = config.get('gui') == 'kivy'
        self.seed_type = None

    def set_icon(self, icon):
        pass

    def run(self, *args):
        action = args[0]
        args = args[1:]
        self.stack.append((action, args))
        if not action:
            return
        if type(action) is tuple:
            self.plugin, action = action
        if self.plugin and hasattr(self.plugin, action):
            f = getattr(self.plugin, action)
            f(self, *args)
        elif hasattr(self, action):
            f = getattr(self, action)
            f(*args)
        else:
            raise Exception("unknown action", action)

    def can_go_back(self):
        return len(self.stack)>1

    def go_back(self):
        if not self.can_go_back():
            return
        self.stack.pop()
        action, args = self.stack.pop()
        self.run(action, *args)

    def new(self):
        name = os.path.basename(self.storage.path)
        title = _("Create") + ' ' + name
        message = '\n'.join([
            _("What kind of wallet do you want to create?")
        ])
        wallet_kinds = [
            ('standard',  _("Standard wallet")),
            ('2fa', _("Wallet with two-factor authentication")),
            ('multisig',  _("Multi-signature wallet")),
            ('imported',  _("Import Litecoin addresses or private keys")),
        ]
        choices = [pair for pair in wallet_kinds if pair[0] in wallet_types]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.on_wallet_type)

    def upgrade_storage(self):
        exc = None
        def on_finished():
            if exc is None:
                self.wallet = Wallet(self.storage)
                self.terminate()
            else:
                raise exc
        def do_upgrade():
            nonlocal exc
            try:
                self.storage.upgrade()
            except Exception as e:
                exc = e
        self.waiting_dialog(do_upgrade, _('Upgrading wallet format...'), on_finished=on_finished)

    def load_2fa(self):
        self.storage.put('wallet_type', '2fa')
        self.storage.put('use_trustedcoin', True)
        self.plugin = self.plugins.load_plugin('trustedcoin')

    def on_wallet_type(self, choice):
        self.wallet_type = choice
        if choice == 'standard':
            action = 'choose_keystore'
        elif choice == 'multisig':
            action = 'choose_multisig'
        elif choice == '2fa':
            self.load_2fa()
            action = self.storage.get_action()
        elif choice == 'imported':
            action = 'import_addresses_or_keys'
        self.run(action)

    def choose_multisig(self):
        def on_multisig(m, n):
            self.multisig_type = "%dof%d"%(m, n)
            self.storage.put('wallet_type', self.multisig_type)
            self.n = n
            self.run('choose_keystore')
        self.multisig_dialog(run_next=on_multisig)

    def choose_keystore(self):
        assert self.wallet_type in ['standard', 'multisig']
        i = len(self.keystores)
        title = _('Add cosigner') + ' (%d of %d)'%(i+1, self.n) if self.wallet_type=='multisig' else _('Keystore')
        if self.wallet_type =='standard' or i==0:
            message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
            choices = [
                ('choose_seed_type', _('Create a new seed')),
                ('restore_from_seed', _('I already have a seed')),
                ('restore_from_key', _('Use a master key')),
            ]
            if not self.is_kivy:
                choices.append(('choose_hw_device',  _('Use a hardware device')))
        else:
            message = _('Add a cosigner to your multi-sig wallet')
            choices = [
                ('restore_from_key', _('Enter cosigner key')),
                ('restore_from_seed', _('Enter cosigner seed')),
            ]
            if not self.is_kivy:
                choices.append(('choose_hw_device',  _('Cosign with hardware device')))

        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def import_addresses_or_keys(self):
        v = lambda x: keystore.is_address_list(x) or keystore.is_private_key_list(x)
        title = _("Import Litecoin Addresses")
        message = _("Enter a list of Litecoin addresses (this will create a watching-only wallet), or a list of private keys.")
        self.add_xpub_dialog(title=title, message=message, run_next=self.on_import,
                             is_valid=v, allow_multi=True, show_wif_help=True)

    def on_import(self, text):
        # create a temporary wallet and exploit that modifications
        # will be reflected on self.storage
        if keystore.is_address_list(text):
            w = Imported_Wallet(self.storage)
            for x in text.split():
                w.import_address(x)
        elif keystore.is_private_key_list(text):
            k = keystore.Imported_KeyStore({})
            self.storage.put('keystore', k.dump())
            w = Imported_Wallet(self.storage)
            for x in keystore.get_private_keys(text):
                w.import_private_key(x, None)
            self.keystores.append(w.keystore)
        else:
            return self.terminate()
        return self.run('create_wallet')

    def restore_from_key(self):
        if self.wallet_type == 'standard':
            v = keystore.is_master_key
            title = _("Create keystore from a master key")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub/ypub/zpub)."),
                _("To create a spending wallet, please enter a master private key (xprv/yprv/zprv).")
            ])
            self.add_xpub_dialog(title=title, message=message, run_next=self.on_restore_from_key, is_valid=v)
        else:
            i = len(self.keystores) + 1
            self.add_cosigner_dialog(index=i, run_next=self.on_restore_from_key, is_valid=keystore.is_bip32_key)

    def on_restore_from_key(self, text):
        k = keystore.from_master_key(text)
        self.on_keystore(k)

    def choose_hw_device(self, purpose=HWD_SETUP_NEW_WALLET):
        title = _('Hardware Keystore')
        # check available plugins
        support = self.plugins.get_hardware_support()
        if not support:
            msg = '\n'.join([
                _('No hardware wallet support found on your system.'),
                _('Please install the relevant libraries (eg python-trezor for Trezor).'),
            ])
            self.confirm_dialog(title=title, message=msg, run_next= lambda x: self.choose_hw_device(purpose))
            return
        # scan devices
        devices = []
        devmgr = self.plugins.device_manager
        try:
            scanned_devices = devmgr.scan_devices()
        except BaseException as e:
            devmgr.print_error('error scanning devices: {}'.format(e))
            debug_msg = '  {}:\n    {}'.format(_('Error scanning devices'), e)
        else:
            debug_msg = ''
            for name, description, plugin in support:
                try:
                    # FIXME: side-effect: unpaired_device_info sets client.handler
                    u = devmgr.unpaired_device_infos(None, plugin, devices=scanned_devices)
                except BaseException as e:
                    devmgr.print_error('error getting device infos for {}: {}'.format(name, e))
                    debug_msg += '  {}:\n    {}\n'.format(plugin.name, e)
                    continue
                devices += list(map(lambda x: (name, x), u))
        if not debug_msg:
            debug_msg = '  {}'.format(_('No exceptions encountered.'))
        if not devices:
            msg = ''.join([
                _('No hardware device detected.') + '\n',
                _('To trigger a rescan, press \'Next\'.') + '\n\n',
                _('If your device is not detected on Windows, go to "Settings", "Devices", "Connected devices", and do "Remove device". Then, plug your device again.') + ' ',
                _('On Linux, you might have to add a new permission to your udev rules.') + '\n\n',
                _('Debug message') + '\n',
                debug_msg
            ])
            self.confirm_dialog(title=title, message=msg, run_next= lambda x: self.choose_hw_device(purpose))
            return
        # select device
        self.devices = devices
        choices = []
        for name, info in devices:
            state = _("initialized") if info.initialized else _("wiped")
            label = info.label or _("An unnamed {}").format(name)
            descr = "%s [%s, %s]" % (label, name, state)
            choices.append(((name, info), descr))
        msg = _('Select a device') + ':'
        self.choice_dialog(title=title, message=msg, choices=choices, run_next= lambda *args: self.on_device(*args, purpose=purpose))

    def on_device(self, name, device_info, *, purpose):
        self.plugin = self.plugins.get_plugin(name)
        try:
            self.plugin.setup_device(device_info, self, purpose)
        except OSError as e:
            self.show_error(_('We encountered an error while connecting to your device:')
                            + '\n' + str(e) + '\n'
                            + _('To try to fix this, we will now re-pair with your device.') + '\n'
                            + _('Please try again.'))
            devmgr = self.plugins.device_manager
            devmgr.unpair_id(device_info.device.id_)
            self.choose_hw_device(purpose)
            return
        except (UserCancelled, GoBack):
            self.choose_hw_device(purpose)
            return
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.show_error(str(e))
            self.choose_hw_device(purpose)
            return
        if purpose == HWD_SETUP_NEW_WALLET:
            def f(derivation, script_type):
                self.run('on_hw_derivation', name, device_info, derivation, script_type)
            self.derivation_and_script_type_dialog(f)
        elif purpose == HWD_SETUP_DECRYPT_WALLET:
            derivation = get_derivation_used_for_hw_device_encryption()
            xpub = self.plugin.get_xpub(device_info.device.id_, derivation, 'standard', self)
            password = keystore.Xpub.get_pubkey_from_xpub(xpub, ())
            try:
                self.storage.decrypt(password)
            except InvalidPassword:
                # try to clear session so that user can type another passphrase
                devmgr = self.plugins.device_manager
                client = devmgr.client_by_id(device_info.device.id_)
                if hasattr(client, 'clear_session'):  # FIXME not all hw wallet plugins have this
                    client.clear_session()
                raise
        else:
            raise Exception('unknown purpose: %s' % purpose)

    def derivation_and_script_type_dialog(self, f):
        message1 = _('Choose the type of addresses in your wallet.')
        message2 = '\n'.join([
            _('You can override the suggested derivation path.'),
            _('If you are not sure what this is, leave this field unchanged.')
        ])
        if self.wallet_type == 'multisig':
            # There is no general standard for HD multisig.
            # For legacy, this is partially compatible with BIP45; assumes index=0
            # For segwit, a custom path is used, as there is no standard at all.
            choices = [
                ('standard',   'legacy multisig (p2sh)',            "m/45'/0"),
                ('p2wsh-p2sh', 'p2sh-segwit multisig (p2wsh-p2sh)', purpose48_derivation(0, xtype='p2wsh-p2sh')),
                ('p2wsh',      'native segwit multisig (p2wsh)',    purpose48_derivation(0, xtype='p2wsh')),
            ]
        else:
            choices = [
                ('standard',    'legacy (p2pkh)',            bip44_derivation(0, bip43_purpose=44)),
                ('p2wpkh-p2sh', 'p2sh-segwit (p2wpkh-p2sh)', bip44_derivation(0, bip43_purpose=49)),
                ('p2wpkh',      'native segwit (p2wpkh)',    bip44_derivation(0, bip43_purpose=84)),
            ]
        while True:
            try:
                self.choice_and_line_dialog(
                    run_next=f, title=_('Script type and Derivation path'), message1=message1,
                    message2=message2, choices=choices, test_text=bitcoin.is_bip32_derivation)
                return
            except ScriptTypeNotSupported as e:
                self.show_error(e)
                # let the user choose again

    def on_hw_derivation(self, name, device_info, derivation, xtype):
        from .keystore import hardware_keystore
        try:
            xpub = self.plugin.get_xpub(device_info.device.id_, derivation, xtype, self)
        except ScriptTypeNotSupported:
            raise  # this is handled in derivation_dialog
        except BaseException as e:
            self.show_error(e)
            return
        d = {
            'type': 'hardware',
            'hw_type': name,
            'derivation': derivation,
            'xpub': xpub,
            'label': device_info.label,
        }
        k = hardware_keystore(d)
        self.on_keystore(k)

    def passphrase_dialog(self, run_next, is_restoring=False):
        title = _('Seed extension')
        message = '\n'.join([
            _('You may extend your seed with custom words.'),
            _('Your seed extension must be saved together with your seed.'),
        ])
        warning = '\n'.join([
            _('Note that this is NOT your encryption password.'),
            _('If you do not know what this is, leave this field empty.'),
        ])
        warn_issue4566 = is_restoring and self.seed_type == 'bip39'
        self.line_dialog(title=title, message=message, warning=warning,
                         default='', test=lambda x:True, run_next=run_next,
                         warn_issue4566=warn_issue4566)

    def restore_from_seed(self):
        self.opt_bip39 = True
        self.opt_ext = True
        is_cosigning_seed = lambda x: bitcoin.seed_type(x) in ['standard', 'segwit']
        test = bitcoin.is_seed if self.wallet_type == 'standard' else is_cosigning_seed
        self.restore_seed_dialog(run_next=self.on_restore_seed, test=test)

    def on_restore_seed(self, seed, is_bip39, is_ext):
        self.seed_type = 'bip39' if is_bip39 else bitcoin.seed_type(seed)
        if self.seed_type == 'bip39':
            f = lambda passphrase: self.on_restore_bip39(seed, passphrase)
            self.passphrase_dialog(run_next=f, is_restoring=True) if is_ext else f('')
        elif self.seed_type in ['standard', 'segwit']:
            f = lambda passphrase: self.run('create_keystore', seed, passphrase)
            self.passphrase_dialog(run_next=f, is_restoring=True) if is_ext else f('')
        elif self.seed_type == 'old':
            self.run('create_keystore', seed, '')
        elif self.seed_type == '2fa':
            self.load_2fa()
            self.run('on_restore_seed', seed, is_ext)
        else:
            raise Exception('Unknown seed type', self.seed_type)

    def on_restore_bip39(self, seed, passphrase):
        def f(derivation, script_type):
            self.run('on_bip43', seed, passphrase, derivation, script_type)
        self.derivation_and_script_type_dialog(f)

    def create_keystore(self, seed, passphrase):
        k = keystore.from_seed(seed, passphrase, self.wallet_type == 'multisig')
        self.on_keystore(k)

    def on_bip43(self, seed, passphrase, derivation, script_type):
        k = keystore.from_bip39_seed(seed, passphrase, derivation, xtype=script_type)
        self.on_keystore(k)

    def on_keystore(self, k):
        has_xpub = isinstance(k, keystore.Xpub)
        if has_xpub:
            from .bitcoin import xpub_type
            t1 = xpub_type(k.xpub)
        if self.wallet_type == 'standard':
            if has_xpub and t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:
                self.show_error(_('Wrong key type') + ' %s'%t1)
                self.run('choose_keystore')
                return
            self.keystores.append(k)
            self.run('create_wallet')
        elif self.wallet_type == 'multisig':
            assert has_xpub
            if t1 not in ['standard', 'p2wsh', 'p2wsh-p2sh']:
                self.show_error(_('Wrong key type') + ' %s'%t1)
                self.run('choose_keystore')
                return
            if k.xpub in map(lambda x: x.xpub, self.keystores):
                self.show_error(_('Error: duplicate master public key'))
                self.run('choose_keystore')
                return
            if len(self.keystores)>0:
                t2 = xpub_type(self.keystores[0].xpub)
                if t1 != t2:
                    self.show_error(_('Cannot add this cosigner:') + '\n' + "Their key type is '%s', we are '%s'"%(t1, t2))
                    self.run('choose_keystore')
                    return
            self.keystores.append(k)
            if len(self.keystores) == 1:
                xpub = k.get_master_public_key()
                self.stack = []
                self.run('show_xpub_and_add_cosigners', xpub)
            elif len(self.keystores) < self.n:
                self.run('choose_keystore')
            else:
                self.run('create_wallet')

    def create_wallet(self):
        encrypt_keystore = any(k.may_have_password() for k in self.keystores)
        # note: the following condition ("if") is duplicated logic from
        # wallet.get_available_storage_encryption_version()
        if self.wallet_type == 'standard' and isinstance(self.keystores[0], keystore.Hardware_KeyStore):
            # offer encrypting with a pw derived from the hw device
            k = self.keystores[0]
            try:
                k.handler = self.plugin.create_handler(self)
                password = k.get_password_for_storage_encryption()
            except UserCancelled:
                devmgr = self.plugins.device_manager
                devmgr.unpair_xpub(k.xpub)
                self.choose_hw_device()
                return
            except BaseException as e:
                traceback.print_exc(file=sys.stderr)
                self.show_error(str(e))
                return
            self.request_storage_encryption(
                run_next=lambda encrypt_storage: self.on_password(
                    password,
                    encrypt_storage=encrypt_storage,
                    storage_enc_version=STO_EV_XPUB_PW,
                    encrypt_keystore=False))
        else:
            # prompt the user to set an arbitrary password
            self.request_password(
                run_next=lambda password, encrypt_storage: self.on_password(
                    password,
                    encrypt_storage=encrypt_storage,
                    storage_enc_version=STO_EV_USER_PW,
                    encrypt_keystore=encrypt_keystore),
                force_disable_encrypt_cb=not encrypt_keystore)

    def on_password(self, password, *, encrypt_storage,
                    storage_enc_version=STO_EV_USER_PW, encrypt_keystore):
        self.storage.set_keystore_encryption(bool(password) and encrypt_keystore)
        if encrypt_storage:
            self.storage.set_password(password, enc_version=storage_enc_version)
        for k in self.keystores:
            if k.may_have_password():
                k.update_password(None, password)
        if self.wallet_type == 'standard':
            self.storage.put('seed_type', self.seed_type)
            keys = self.keystores[0].dump()
            self.storage.put('keystore', keys)
            self.wallet = Standard_Wallet(self.storage)
            self.run('create_addresses')
        elif self.wallet_type == 'multisig':
            for i, k in enumerate(self.keystores):
                self.storage.put('x%d/'%(i+1), k.dump())
            self.storage.write()
            self.wallet = Multisig_Wallet(self.storage)
            self.run('create_addresses')
        elif self.wallet_type == 'imported':
            if len(self.keystores) > 0:
                keys = self.keystores[0].dump()
                self.storage.put('keystore', keys)
            self.wallet = Imported_Wallet(self.storage)
            self.wallet.storage.write()
            self.terminate()

    def show_xpub_and_add_cosigners(self, xpub):
        self.show_xpub_dialog(xpub=xpub, run_next=lambda x: self.run('choose_keystore'))

    def choose_seed_type(self):
        title = _('Choose Seed type')
        message = ' '.join([
            _("The type of addresses used by your wallet will depend on your seed."),
            _("Segwit wallets use bech32 addresses, defined in BIP173."),
            _("Please note that websites and other wallets may not support these addresses yet."),
            _("Thus, you might want to keep using a non-segwit wallet in order to be able to receive litecoins during the transition period.")
        ])
        choices = [
            ('create_standard_seed', _('Standard')),
            ('create_segwit_seed', _('Segwit')),
        ]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def create_segwit_seed(self): self.create_seed('segwit')
    def create_standard_seed(self): self.create_seed('standard')

    def create_seed(self, seed_type):
        from . import mnemonic
        self.seed_type = seed_type
        seed = mnemonic.Mnemonic('en').make_seed(self.seed_type)
        self.opt_bip39 = False
        f = lambda x: self.request_passphrase(seed, x)
        self.show_seed_dialog(run_next=f, seed_text=seed)

    def request_passphrase(self, seed, opt_passphrase):
        if opt_passphrase:
            f = lambda x: self.confirm_seed(seed, x)
            self.passphrase_dialog(run_next=f)
        else:
            self.run('confirm_seed', seed, '')

    def confirm_seed(self, seed, passphrase):
        f = lambda x: self.confirm_passphrase(seed, passphrase)
        self.confirm_seed_dialog(run_next=f, test=lambda x: x==seed)

    def confirm_passphrase(self, seed, passphrase):
        f = lambda x: self.run('create_keystore', seed, x)
        if passphrase:
            title = _('Confirm Seed Extension')
            message = '\n'.join([
                _('Your seed extension must be saved together with your seed.'),
                _('Please type it here.'),
            ])
            self.line_dialog(run_next=f, title=title, message=message, default='', test=lambda x: x==passphrase)
        else:
            f('')

    def create_addresses(self):
        def task():
            self.wallet.synchronize()
            self.wallet.storage.write()
            self.terminate()
        msg = _("Electrum is generating your addresses, please wait...")
        self.waiting_dialog(task, msg)
