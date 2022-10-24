import copy
import os

from typing import List, TYPE_CHECKING, Tuple, NamedTuple, Any, Dict, Optional, Union

from electrum.logging import get_logger
from electrum.storage import WalletStorage, StorageEncryptionVersion
from electrum.wallet_db import WalletDB
from electrum.bip32 import normalize_bip32_derivation, xpub_type
from electrum import keystore
from electrum import bitcoin

class WizardViewState(NamedTuple):
    view: str
    wizard_data: Dict[str, Any]
    params: Dict[str, Any]

class AbstractWizard:
    # serve as a base for all UIs, so no qt
    # encapsulate wizard state
    # encapsulate navigation decisions, UI agnostic
    # encapsulate stack, go backwards
    # allow extend/override flow in subclasses e.g.
    # - override: replace 'next' value to own fn
    # - extend: add new keys to navmap, wire up flow by override

    _logger = get_logger(__name__)

    navmap = {}

    _current = WizardViewState(None, {}, {})
    _stack = [] # type: List[WizardViewState]

    def navmap_merge(self, additional_navmap):
        # NOTE: only merges one level deep. Deeper dict levels will overwrite
        for k,v in additional_navmap.items():
            if k in self.navmap:
                self.navmap[k].update(v)
            else:
                self.navmap[k] = v

    # from current view and wizard_data, resolve the new view
    # returns WizardViewState tuple (view name, wizard_data, view params)
    # view name is the string id of the view in the nav map
    # wizard data is the (stacked) wizard data dict containing user input and choices
    # view params are transient, meant for extra configuration of a view (e.g. info
    #   msg in a generic choice dialog)
    # exception: stay on this view
    def resolve_next(self, view, wizard_data):
        assert view
        self._logger.debug(f'view={view}')
        assert view in self.navmap

        nav = self.navmap[view]

        if 'accept' in nav:
            # allow python scope to append to wizard_data before
            # adding to stack or finishing
            if callable(nav['accept']):
                nav['accept'](wizard_data)
            else:
                self._logger.error(f'accept handler for view {view} not callable')

        if not 'next' in nav:
            # finished
            self.finished(wizard_data)
            return (None, wizard_data, {})

        nexteval = nav['next']
        # simple string based next view
        if isinstance(nexteval, str):
            new_view = WizardViewState(nexteval, wizard_data, {})
        else:
            # handler fn based next view
            nv = nexteval(wizard_data)
            self._logger.debug(repr(nv))

            # append wizard_data and params if not returned
            if isinstance(nv, str):
                new_view = WizardViewState(nv, wizard_data, {})
            elif len(nv) == 1:
                new_view = WizardViewState(nv[0], wizard_data, {})
            elif len(nv) == 2:
                new_view = WizardViewState(nv[0], nv[1], {})
            else:
                new_view = nv

        self._stack.append(copy.deepcopy(self._current))
        self._current = new_view

        self._logger.debug(f'resolve_next view is {self._current.view}')
        self._logger.debug('stack:' + repr(self._stack))

        return new_view

    def resolve_prev(self):
        prev_view = self._stack.pop()
        self._logger.debug(f'resolve_prev view is {prev_view}')
        self._logger.debug('stack:' + repr(self._stack))
        self._current = prev_view
        return prev_view

    # check if this view is the final view
    def is_last_view(self, view, wizard_data):
        assert view
        assert view in self.navmap

        nav = self.navmap[view]

        if not 'last' in nav:
            return False

        lastnav = nav['last']
        # bool literal
        if isinstance(lastnav, bool):
            return lastnav
        elif callable(lastnav):
            # handler fn based
            l = lastnav(view, wizard_data)
            self._logger.debug(f'view "{view}" last: {l}')
            return l
        else:
            raise Exception('last handler for view {view} is not callable nor a bool literal')

    def finished(self, wizard_data):
        self._logger.debug('finished.')

    def reset(self):
        self.stack = []
        self._current = WizardViewState(None, {}, {})

class NewWalletWizard(AbstractWizard):

    _logger = get_logger(__name__)

    def __init__(self, daemon):
        self.navmap = {
            'wallet_name': {
                'next': 'wallet_type'
            },
            'wallet_type': {
                'next': self.on_wallet_type
            },
            'keystore_type': {
                'next': self.on_keystore_type
            },
            'create_seed': {
                'next': 'confirm_seed'
            },
            'confirm_seed': {
                'next': 'wallet_password',
                'last': self.last_if_single_password
            },
            'have_seed': {
                'next': self.on_have_seed,
                'last': self.last_if_single_password_and_not_bip39
            },
            'bip39_refine': {
                'next': 'wallet_password',
                'last': self.last_if_single_password
            },
            'have_master_key': {
                'next': 'wallet_password',
                'last': self.last_if_single_password
            },
            'imported': {
                'next': 'wallet_password',
                'last': self.last_if_single_password
            },
            'wallet_password': {
                'last': True
            }
        }
        self._daemon = daemon

    def start(self, initial_data = {}):
        self.reset()
        self._current = WizardViewState('wallet_name', initial_data, {})
        return self._current

    def last_if_single_password(self, view, wizard_data):
        raise NotImplementedError()

    def last_if_single_password_and_not_bip39(self, view, wizard_data):
        return self.last_if_single_password(view, wizard_data) and not wizard_data['seed_variant'] == 'bip39'

    def on_wallet_type(self, wizard_data):
        t = wizard_data['wallet_type']
        return {
            'standard': 'keystore_type',
            '2fa': 'trustedcoin_start',
            'imported': 'imported'
        }.get(t)

    def on_keystore_type(self, wizard_data):
        t = wizard_data['keystore_type']
        return {
            'createseed': 'create_seed',
            'haveseed': 'have_seed',
            'masterkey': 'have_master_key'
        }.get(t)

    def on_have_seed(self, wizard_data):
        if (wizard_data['seed_type'] == 'bip39'):
            return 'bip39_refine'
        else:
            return 'wallet_password'

    def finished(self, wizard_data):
        self._logger.debug('finished')
        # override

    def create_storage(self, path, data):
        # only standard and 2fa wallets for now
        assert data['wallet_type'] in ['standard', '2fa', 'imported']

        if os.path.exists(path):
            raise Exception('file already exists at path')
        storage = WalletStorage(path)

        k = None
        if not 'keystore_type' in data:
            assert data['wallet_type'] == 'imported'
            addresses = {}
            if 'private_key_list' in data:
                k = keystore.Imported_KeyStore({})
                keys = keystore.get_private_keys(data['private_key_list'])
                for pk in keys:
                    assert bitcoin.is_private_key(pk)
                    txin_type, pubkey = k.import_privkey(pk, None)
                    addr = bitcoin.pubkey_to_address(txin_type, pubkey)
                    addresses[addr] = {'type': txin_type, 'pubkey': pubkey}
            elif 'address_list' in data:
                for addr in data['address_list'].split():
                    addresses[addr] = {}
        elif data['keystore_type'] in ['createseed', 'haveseed']:
            if data['seed_type'] in ['old', 'standard', 'segwit']:
                self._logger.debug('creating keystore from electrum seed')
                k = keystore.from_seed(data['seed'], data['seed_extra_words'], data['wallet_type'] == 'multisig')
            elif data['seed_type'] == 'bip39':
                self._logger.debug('creating keystore from bip39 seed')
                root_seed = keystore.bip39_to_seed(data['seed'], data['seed_extra_words'])
                derivation = normalize_bip32_derivation(data['derivation_path'])
                script = data['script_type'] if data['script_type'] != 'p2pkh' else 'standard'
                k = keystore.from_bip43_rootseed(root_seed, derivation, xtype=script)
            elif data['seed_type'] == '2fa_segwit': # TODO: legacy 2fa '2fa'
                self._logger.debug('creating keystore from 2fa seed')
                k = keystore.from_xprv(data['x1/']['xprv'])
            else:
                raise Exception('unsupported/unknown seed_type %s' % data['seed_type'])
        elif data['keystore_type'] == 'masterkey':
            k = keystore.from_master_key(data['master_key'])
            has_xpub = isinstance(k, keystore.Xpub)
            assert has_xpub
            t1 = xpub_type(k.xpub)
            if t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:
                raise Exception('wrong key type %s' % t1)
        else:
            raise Exception('unsupported/unknown keystore_type %s' % data['keystore_type'])

        if data['encrypt']:
            if k and k.may_have_password():
                k.update_password(None, data['password'])
            storage.set_password(data['password'], enc_version=StorageEncryptionVersion.USER_PASSWORD)

        db = WalletDB('', manual_upgrades=False)
        db.set_keystore_encryption(bool(data['password']) and data['encrypt'])

        db.put('wallet_type', data['wallet_type'])
        if 'seed_type' in data:
            db.put('seed_type', data['seed_type'])

        if data['wallet_type'] == 'standard':
            db.put('keystore', k.dump())
        elif data['wallet_type'] == '2fa':
            db.put('x1/', k.dump())
            if data['trustedcoin_keepordisable'] == 'disable':
                k2 = keystore.from_xprv(data['x2/']['xprv'])
                if data['encrypt'] and k2.may_have_password():
                    k2.update_password(None, data['password'])
                db.put('x2/', k2.dump())
            else:
                db.put('x2/', data['x2/'])
            db.put('x3/', data['x3/'])
            db.put('use_trustedcoin', True)
        elif data['wallet_type'] == 'imported':
            if k:
                db.put('keystore', k.dump())
            db.put('addresses', addresses)

        if k and k.can_have_deterministic_lightning_xprv():
            db.put('lightning_xprv', k.get_lightning_xprv(data['password'] if data['encrypt'] else None))

        db.load_plugins()
        db.write(storage)

class ServerConnectWizard(AbstractWizard):

    _logger = get_logger(__name__)

    def __init__(self, daemon):
        self.navmap = {
            'autoconnect': {
                'next': 'proxy_config',
                'last': lambda v,d: d['autoconnect']
            },
            'proxy_config': {
                'next': 'server_config'
            },
            'server_config': {
                'last': True
            }
        }
        self._daemon = daemon

    def start(self, initial_data = {}):
        self.reset()
        self._current = WizardViewState('autoconnect', initial_data, {})
        return self._current
