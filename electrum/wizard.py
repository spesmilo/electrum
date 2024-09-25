import copy
import os

from typing import List, NamedTuple, Any, Dict, Optional, Tuple, TYPE_CHECKING

from electrum.i18n import _
from electrum.interface import ServerAddr
from electrum.keystore import hardware_keystore
from electrum.logging import get_logger
from electrum.plugin import run_hook
from electrum.slip39 import EncryptedSeed
from electrum.storage import WalletStorage, StorageEncryptionVersion
from electrum.wallet_db import WalletDB
from electrum.bip32 import normalize_bip32_derivation, xpub_type
from electrum import keystore, mnemonic, bitcoin
from electrum.mnemonic import is_any_2fa_seed_type, can_seed_have_passphrase

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.plugin import Plugins
    from electrum.keystore import Hardware_KeyStore


class WizardViewState(NamedTuple):
    view: Optional[str]
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

    def __init__(self):
        self.navmap = {}

        self._current = WizardViewState(None, {}, {})
        self._stack = []  # type: List[WizardViewState]

    def navmap_merge(self, additional_navmap: dict):
        # NOTE: only merges one level deep. Deeper dict levels will overwrite
        for k, v in additional_navmap.items():
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
    def resolve_next(self, view: str, wizard_data: dict) -> WizardViewState:
        assert view, f'view not defined: {repr(self.sanitize_stack_item(wizard_data))}'
        self._logger.debug(f'view={view}')
        assert view in self.navmap

        nav = self.navmap[view]

        if 'accept' in nav:
            # allow python scope to append to wizard_data before
            # adding to stack or finishing
            view_accept = nav['accept']
            if callable(view_accept):
                view_accept(wizard_data)
            else:
                raise Exception(f'accept handler for view {view} is not callable')

        # make a clone for next view
        wizard_data = copy.deepcopy(wizard_data)

        if 'next' not in nav:
            new_view = WizardViewState(None, wizard_data, {})
        else:
            view_next = nav['next']
            if isinstance(view_next, str):
                # string literal
                new_view = WizardViewState(view_next, wizard_data, {})
            elif callable(view_next):
                # handler fn based
                nv = view_next(wizard_data)
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
            else:
                raise Exception(f'next handler for view {view} is not callable nor a string literal')

            if 'params' in self.navmap[new_view.view]:
                params = self.navmap[new_view.view]['params']
                assert isinstance(params, dict), 'params is not a dict'
                new_view.params.update(params)

            self._logger.debug(f'resolve_next view is {new_view.view}')

        self._stack.append(copy.deepcopy(self._current))
        self._current = new_view

        self.log_stack()

        return new_view

    def resolve_prev(self):
        self._current = self._stack.pop()

        self._logger.debug(f'resolve_prev view is "{self._current.view}"')
        self.log_stack()

        return self._current

    # check if this view is the final view
    def is_last_view(self, view: str, wizard_data: dict) -> bool:
        assert view, f'view not defined: {repr(self.sanitize_stack_item(wizard_data))}'
        assert view in self.navmap

        nav = self.navmap[view]

        if 'last' not in nav:
            return False

        view_last = nav['last']
        if isinstance(view_last, bool):
            # bool literal
            self._logger.debug(f'view "{view}" last: {view_last}')
            return view_last
        elif callable(view_last):
            # handler fn based
            is_last = view_last(wizard_data)
            self._logger.debug(f'view "{view}" last: {is_last}')
            return is_last
        else:
            raise Exception(f'last handler for view {view} is not callable nor a bool literal')

    def reset(self):
        self._stack = []
        self._current = WizardViewState(None, {}, {})

    def log_stack(self):
        logstr = 'wizard stack:'
        i = 0
        for item in self._stack:
            ssi = self.sanitize_stack_item(item.wizard_data)
            logstr += f'\n{i}: {hex(id(item.wizard_data))} - {repr(ssi)}'
            i += 1
        sci = self.sanitize_stack_item(self._current.wizard_data)
        logstr += f'\nc: {hex(id(self._current.wizard_data))} - {repr(sci)}'
        self._logger.debug(logstr)

    def sanitize_stack_item(self, _stack_item) -> dict:
        whitelist = [
            "wallet_name", "wallet_exists", "wallet_is_open", "wallet_needs_hw_unlock",
            "wallet_type", "keystore_type", "seed_variant", "seed_type", "seed_extend",
            "script_type", "derivation_path", "encrypt",
            # hardware devices:
            "hardware_device", "hw_type", "label", "soft_device_id",
            # inside keystore:
            "type", "pw_hash_version", "derivation", "root_fingerprint",
            # multisig:
            "multisig_participants", "multisig_signatures", "multisig_current_cosigner", "cosigner_keystore_type",
            # trustedcoin:
            "trustedcoin_keepordisable", "trustedcoin_go_online",
        ]

        def sanitize(_dict):
            result = {}
            for item in _dict:
                if isinstance(_dict[item], dict):
                    result[item] = sanitize(_dict[item])
                else:
                    if item in whitelist:
                        result[item] = _dict[item]
                    else:
                        result[item] = '<redacted>'
            return result
        return sanitize(_stack_item)

    def get_wizard_data(self) -> dict:
        return copy.deepcopy(self._current.wizard_data)


class NewWalletWizard(AbstractWizard):

    _logger = get_logger(__name__)

    def __init__(self, daemon: 'Daemon', plugins: 'Plugins'):
        AbstractWizard.__init__(self)
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
                'next': self.on_have_or_confirm_seed,
                'accept': self.maybe_master_pubkey,
                'last': lambda d: self.is_single_password() and not self.is_multisig(d)
            },
            'have_seed': {
                'next': self.on_have_or_confirm_seed,
                'accept': self.maybe_master_pubkey,
                'last': lambda d: self.is_single_password() and not
                                  (self.needs_derivation_path(d) or self.is_multisig(d))
            },
            'choose_hardware_device': {
                'next': self.on_hardware_device,
            },
            'script_and_derivation': {
                'next': lambda d: self.wallet_password_view(d) if not self.is_multisig(d) else 'multisig_cosigner_keystore',
                'accept': self.maybe_master_pubkey,
                'last': lambda d: self.is_single_password() and not self.is_multisig(d)
            },
            'have_master_key': {
                'next': lambda d: self.wallet_password_view(d) if not self.is_multisig(d) else 'multisig_cosigner_keystore',
                'accept': self.maybe_master_pubkey,
                'last': lambda d: self.is_single_password() and not self.is_multisig(d)
            },
            'multisig': {
                'next': 'keystore_type'
            },
            'multisig_cosigner_keystore': {  # this view should set 'multisig_current_cosigner'
                'next': self.on_cosigner_keystore_type
            },
            'multisig_cosigner_key': {
                'next': lambda d: self.wallet_password_view(d) if self.last_cosigner(d) else 'multisig_cosigner_keystore',
                'last': lambda d: self.is_single_password() and self.last_cosigner(d)
            },
            'multisig_cosigner_seed': {
                'next': self.on_have_cosigner_seed,
                'last': lambda d: self.is_single_password() and self.last_cosigner(d) and not self.needs_derivation_path(d)
            },
            'multisig_cosigner_hardware': {
                'next': self.on_hardware_device,
            },
            'multisig_cosigner_script_and_derivation': {
                'next': lambda d: self.wallet_password_view(d) if self.last_cosigner(d) else 'multisig_cosigner_keystore',
                'last': lambda d: self.is_single_password() and self.last_cosigner(d)
            },
            'imported': {
                'next': 'wallet_password',
                'last': lambda d: self.is_single_password()
            },
            'wallet_password': {
                'last': True
            },
            'wallet_password_hardware': {
                'last': True
            }
        }
        self._daemon = daemon
        self.plugins = plugins

    def start(self, initial_data: dict = None) -> WizardViewState:
        if initial_data is None:
            initial_data = {}
        self.reset()
        start_view = 'wallet_name'
        params = self.navmap[start_view].get('params', {})
        self._current = WizardViewState(start_view, initial_data, params)
        return self._current

    def is_single_password(self) -> bool:
        raise NotImplementedError()

    # returns (sub)dict of current cosigner (or root if first)
    def current_cosigner(self, wizard_data: dict) -> dict:
        wdata = wizard_data
        if wizard_data.get('wallet_type') == 'multisig' and 'multisig_current_cosigner' in wizard_data:
            cosigner = wizard_data['multisig_current_cosigner']
            wdata = wizard_data['multisig_cosigner_data'][str(cosigner)]
        return wdata

    def needs_derivation_path(self, wizard_data: dict) -> bool:
        wdata = self.current_cosigner(wizard_data)
        return 'seed_variant' in wdata and wdata['seed_variant'] in ['bip39', 'slip39']

    def wants_ext(self, wizard_data: dict) -> bool:
        wdata = self.current_cosigner(wizard_data)
        return 'seed_variant' in wdata and wdata['seed_extend']

    def is_multisig(self, wizard_data: dict) -> bool:
        return wizard_data['wallet_type'] == 'multisig'

    def on_wallet_type(self, wizard_data: dict) -> str:
        t = wizard_data['wallet_type']
        return {
            'standard': 'keystore_type',
            '2fa': 'trustedcoin_start',
            'multisig': 'multisig',
            'imported': 'imported'
        }.get(t)

    def on_keystore_type(self, wizard_data: dict) -> str:
        t = wizard_data['keystore_type']
        return {
            'createseed': 'create_seed',
            'haveseed': 'have_seed',
            'masterkey': 'have_master_key',
            'hardware': 'choose_hardware_device'
        }.get(t)

    def is_hardware(self, wizard_data: dict) -> bool:
        return wizard_data['keystore_type'] == 'hardware'

    def wallet_password_view(self, wizard_data: dict) -> str:
        if self.is_hardware(wizard_data) and wizard_data['wallet_type'] == 'standard':
            return 'wallet_password_hardware'
        return 'wallet_password'

    def on_hardware_device(self, wizard_data: dict, new_wallet=True) -> str:
        current_cosigner = self.current_cosigner(wizard_data)
        _type, _info = current_cosigner['hardware_device']
        run_hook('init_wallet_wizard', self)  # TODO: currently only used for hww, hook name might be confusing
        plugin = self.plugins.get_plugin(_type)
        return plugin.wizard_entry_for_device(_info, new_wallet=new_wallet)

    def on_have_or_confirm_seed(self, wizard_data: dict) -> str:
        if self.needs_derivation_path(wizard_data):
            return 'script_and_derivation'
        elif self.is_multisig(wizard_data):
            return 'multisig_cosigner_keystore'
        else:
            return 'wallet_password'

    def maybe_master_pubkey(self, wizard_data: dict):
        self._logger.debug('maybe_master_pubkey')
        if self.needs_derivation_path(wizard_data) and 'derivation_path' not in wizard_data:
            self._logger.debug('deferred, missing derivation_path')
            return

        wizard_data['multisig_master_pubkey'] = self.keystore_from_data(wizard_data['wallet_type'], wizard_data).get_master_public_key()

    def on_cosigner_keystore_type(self, wizard_data: dict) -> str:
        t = wizard_data['cosigner_keystore_type']
        return {
            'masterkey': 'multisig_cosigner_key',
            'haveseed': 'multisig_cosigner_seed',
            'hardware': 'multisig_cosigner_hardware'
        }.get(t)

    def on_have_cosigner_seed(self, wizard_data: dict) -> str:
        current_cosigner = self.current_cosigner(wizard_data)
        if self.needs_derivation_path(wizard_data) and 'derivation_path' not in current_cosigner:
            return 'multisig_cosigner_script_and_derivation'
        elif self.last_cosigner(wizard_data):
            return 'wallet_password'
        else:
            return 'multisig_cosigner_keystore'

    def last_cosigner(self, wizard_data: dict) -> bool:
        # check if we have the final number of cosigners. Doesn't check if cosigner data itself is complete
        # (should be validated by wizardcomponents)
        if not self.is_multisig(wizard_data):
            return True

        if len(wizard_data['multisig_cosigner_data']) < (wizard_data['multisig_participants'] - 1):
            return False

        return True

    def has_duplicate_masterkeys(self, wizard_data: dict) -> bool:
        """Multisig wallets need distinct master keys. If True, need to prevent wallet-creation."""
        xpubs = [self.keystore_from_data(wizard_data['wallet_type'], wizard_data).get_master_public_key()]
        for cosigner in wizard_data['multisig_cosigner_data']:
            data = wizard_data['multisig_cosigner_data'][cosigner]
            xpubs.append(self.keystore_from_data(wizard_data['wallet_type'], data).get_master_public_key())
        assert xpubs
        return len(xpubs) != len(set(xpubs))

    def has_heterogeneous_masterkeys(self, wizard_data: dict) -> bool:
        """Multisig wallets need homogeneous master keys.
        All master keys need to be bip32, and e.g. Ypub cannot be mixed with Zpub.
        If True, need to prevent wallet-creation.
        """
        xpubs = [self.keystore_from_data(wizard_data['wallet_type'], wizard_data).get_master_public_key()]
        for cosigner in wizard_data['multisig_cosigner_data']:
            data = wizard_data['multisig_cosigner_data'][cosigner]
            xpubs.append(self.keystore_from_data(wizard_data['wallet_type'], data).get_master_public_key())
        assert xpubs
        try:
            k_xpub_type = xpub_type(xpubs[0])
        except Exception:
            return True  # maybe old_mpk?
        for xpub in xpubs:
            try:
                my_xpub_type = xpub_type(xpub)
            except Exception:
                return True  # maybe old_mpk?
            if my_xpub_type != k_xpub_type:
                return True
        return False

    def keystore_from_data(self, wallet_type: str, data: dict):
        if data['keystore_type'] in ['createseed', 'haveseed'] and 'seed' in data:
            if data['seed_variant'] == 'electrum':
                return keystore.from_seed(data['seed'], passphrase=data['seed_extra_words'], for_multisig=True)
            elif data['seed_variant'] == 'bip39':
                root_seed = keystore.bip39_to_seed(data['seed'], passphrase=data['seed_extra_words'])
                derivation = normalize_bip32_derivation(data['derivation_path'])
                if wallet_type == 'multisig':
                    script = data['script_type'] if data['script_type'] != 'p2sh' else 'standard'
                else:
                    script = data['script_type'] if data['script_type'] != 'p2pkh' else 'standard'
                return keystore.from_bip43_rootseed(root_seed, derivation=derivation, xtype=script)
            elif data['seed_variant'] == 'slip39':
                root_seed = data['seed'].decrypt(data['seed_extra_words'])
                derivation = normalize_bip32_derivation(data['derivation_path'])
                if wallet_type == 'multisig':
                    script = data['script_type'] if data['script_type'] != 'p2sh' else 'standard'
                else:
                    script = data['script_type'] if data['script_type'] != 'p2pkh' else 'standard'
                return keystore.from_bip43_rootseed(root_seed, derivation=derivation, xtype=script)
            else:
                raise Exception('Unsupported seed variant %s' % data['seed_variant'])
        elif data['keystore_type'] == 'masterkey' and 'master_key' in data:
            return keystore.from_master_key(data['master_key'])
        elif data['keystore_type'] == 'hardware':
            return self.hw_keystore(data)
        else:
            raise Exception('no seed or master_key in data')

    def is_current_cosigner_hardware(self, wizard_data: dict) -> bool:
        cosigner_data = self.current_cosigner(wizard_data)
        cosigner_is_hardware = cosigner_data == wizard_data and wizard_data['keystore_type'] == 'hardware'
        if 'cosigner_keystore_type' in wizard_data and wizard_data['cosigner_keystore_type'] == 'hardware':
            cosigner_is_hardware = True
        return cosigner_is_hardware

    def check_multisig_constraints(self, wizard_data: dict) -> Tuple[bool, str]:
        if not self.is_multisig(wizard_data):
            return True, ''

        # current cosigner might be incomplete. In that case, return valid
        cosigner_data = self.current_cosigner(wizard_data)
        if self.needs_derivation_path(wizard_data):
            if 'derivation_path' not in cosigner_data:
                self._logger.debug('defer multisig check: missing derivation_path')
                return True, ''
        if self.wants_ext(wizard_data):
            if 'seed_extra_words' not in cosigner_data:
                self._logger.debug('defer multisig check: missing extra words')
                return True, ''
        if self.is_current_cosigner_hardware(wizard_data):
            if 'master_key' not in cosigner_data:
                self._logger.debug('defer multisig check: missing master_key')
                return True, ''

        user_info = ''

        if self.has_duplicate_masterkeys(wizard_data):
            self._logger.debug('Duplicate master keys!')
            user_info = _('Duplicate master keys')
            multisig_keys_valid = False
        elif self.has_heterogeneous_masterkeys(wizard_data):
            self._logger.debug('Heterogenous master keys!')
            user_info = _('Heterogenous master keys')
            multisig_keys_valid = False
        else:
            multisig_keys_valid = True

        return multisig_keys_valid, user_info

    def validate_seed(self, seed: str, seed_variant: str, wallet_type: str):
        seed_type = ''
        seed_valid = False
        validation_message = ''
        can_passphrase = True

        if seed_variant == 'electrum':
            seed_type = mnemonic.calc_seed_type(seed)
            if seed_type != '':
                seed_valid = True
                can_passphrase = can_seed_have_passphrase(seed)
        elif seed_variant == 'bip39':
            is_checksum, is_wordlist = keystore.bip39_is_checksum_valid(seed)
            validation_message = ('' if is_checksum else _('BIP39 checksum failed')) if is_wordlist else _('Unknown BIP39 wordlist')
            if not bool(seed):
                validation_message = ''
            seed_type = 'bip39'
            # bip39 always valid, even if checksum failed, see #8720
            # however, reject empty string
            seed_valid = bool(seed)
        elif seed_variant == 'slip39':
            # seed shares should be already validated by wizard page, we have a combined encrypted seed
            if seed and isinstance(seed, EncryptedSeed):
                seed_valid = True
                seed_type = 'slip39'
            else:
                seed_valid = False
        else:
            raise Exception(f'unknown seed variant {seed_variant}')

        # check if seed matches wallet type
        if wallet_type == '2fa' and not is_any_2fa_seed_type(seed_type):
            seed_valid = False
        elif wallet_type == 'standard' and seed_type not in ['old', 'standard', 'segwit', 'bip39', 'slip39']:
            seed_valid = False
        elif wallet_type == 'multisig' and seed_type not in ['standard', 'segwit', 'bip39', 'slip39']:
            seed_valid = False

        self._logger.debug(f'seed verified: {seed_valid}, type={seed_type!r}, validation_message={validation_message}')

        return seed_valid, seed_type, validation_message, can_passphrase

    def create_storage(self, path: str, data: dict):
        assert data['wallet_type'] in ['standard', '2fa', 'imported', 'multisig']

        if os.path.exists(path):
            raise Exception('file already exists at path')
        storage = WalletStorage(path)

        # TODO: refactor using self.keystore_from_data
        k = None
        if 'keystore_type' not in data:
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
                k = keystore.from_seed(data['seed'], passphrase=data['seed_extra_words'], for_multisig=data['wallet_type'] == 'multisig')
            elif data['seed_type'] in ['bip39', 'slip39']:
                self._logger.debug('creating keystore from %s seed' % data['seed_type'])
                if data['seed_type'] == 'bip39':
                    root_seed = keystore.bip39_to_seed(data['seed'], passphrase=data['seed_extra_words'])
                else:
                    root_seed = data['seed'].decrypt(data['seed_extra_words'])
                derivation = normalize_bip32_derivation(data['derivation_path'])
                if data['wallet_type'] == 'multisig':
                    script = data['script_type'] if data['script_type'] != 'p2sh' else 'standard'
                else:
                    script = data['script_type'] if data['script_type'] != 'p2pkh' else 'standard'
                k = keystore.from_bip43_rootseed(root_seed, derivation=derivation, xtype=script)
            elif is_any_2fa_seed_type(data['seed_type']):
                self._logger.debug('creating keystore from 2fa seed')
                k = keystore.from_xprv(data['x1']['xprv'])
            else:
                raise Exception('unsupported/unknown seed_type %s' % data['seed_type'])
        elif data['keystore_type'] == 'masterkey':
            k = keystore.from_master_key(data['master_key'])
            if isinstance(k, keystore.Xpub):  # has xpub
                t1 = xpub_type(k.xpub)
                if data['wallet_type'] == 'multisig':
                    if t1 not in ['standard', 'p2wsh', 'p2wsh-p2sh']:
                        raise Exception('wrong key type %s' % t1)
                else:
                    if t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:
                        raise Exception('wrong key type %s' % t1)
            elif isinstance(k, keystore.Old_KeyStore):
                pass
            else:
                raise Exception(f'unexpected keystore type: {type(k)}')
        elif data['keystore_type'] == 'hardware':
            k = self.hw_keystore(data)
            if isinstance(k, keystore.Xpub):  # has xpub
                t1 = xpub_type(k.xpub)
                if data['wallet_type'] == 'multisig':
                    if t1 not in ['standard', 'p2wsh', 'p2wsh-p2sh']:
                        raise Exception('wrong key type %s' % t1)
                else:
                    if t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:
                        raise Exception('wrong key type %s' % t1)
            else:
                raise Exception(f'unexpected keystore type: {type(k)}')
        else:
            raise Exception('unsupported/unknown keystore_type %s' % data['keystore_type'])

        if data['password']:
            if k and k.may_have_password():
                k.update_password(None, data['password'])

        if data['encrypt']:
            enc_version = StorageEncryptionVersion.USER_PASSWORD
            if data.get('keystore_type') == 'hardware' and data['wallet_type'] == 'standard':
                enc_version = StorageEncryptionVersion.XPUB_PASSWORD
            storage.set_password(data['password'], enc_version=enc_version)

        db = WalletDB('', storage=storage, upgrade=True)
        db.set_keystore_encryption(bool(data['password']))

        db.put('wallet_type', data['wallet_type'])

        if data['wallet_type'] == 'standard':
            db.put('keystore', k.dump())
        elif data['wallet_type'] == '2fa':
            db.put('x1', k.dump())
            if 'trustedcoin_keepordisable' in data and data['trustedcoin_keepordisable'] == 'disable':
                k2 = keystore.from_xprv(data['x2']['xprv'])
                if data['encrypt'] and k2.may_have_password():
                    k2.update_password(None, data['password'])
                db.put('x2', k2.dump())
            else:
                db.put('x2', data['x2'])
            if 'x3' in data:
                db.put('x3', data['x3'])
            db.put('use_trustedcoin', True)
        elif data['wallet_type'] == 'multisig':
            if not isinstance(k, keystore.Xpub):
                raise Exception(f'unexpected keystore(main) type={type(k)} in multisig. not bip32.')
            k_xpub_type = xpub_type(k.xpub)
            db.put('wallet_type', '%dof%d' % (data['multisig_signatures'], data['multisig_participants']))
            db.put('x1', k.dump())
            for cosigner in data['multisig_cosigner_data']:
                cosigner_keystore = self.keystore_from_data('multisig', data['multisig_cosigner_data'][cosigner])
                if not isinstance(cosigner_keystore, keystore.Xpub):
                    raise Exception(f'unexpected keystore(cosigner) type={type(cosigner_keystore)} in multisig. not bip32.')
                if k_xpub_type != xpub_type(cosigner_keystore.xpub):
                    raise Exception('multisig wallet needs to have homogeneous xpub types')
                if data['encrypt'] and cosigner_keystore.may_have_password():
                    cosigner_keystore.update_password(None, data['password'])
                db.put(f'x{cosigner}', cosigner_keystore.dump())
        elif data['wallet_type'] == 'imported':
            if k:
                db.put('keystore', k.dump())
            db.put('addresses', addresses)

        if k and k.can_have_deterministic_lightning_xprv():
            db.put('lightning_xprv', k.get_lightning_xprv(data['password']))

        db.load_plugins()
        db.write()

    def hw_keystore(self, data: dict) -> 'Hardware_KeyStore':
        return hardware_keystore({
            'type': 'hardware',
            'hw_type': data['hw_type'],
            'derivation': data['derivation_path'],
            'root_fingerprint': data['root_fingerprint'],
            'xpub': data['master_key'],
            'label': data['label'],
            'soft_device_id': data['soft_device_id']
        })


class ServerConnectWizard(AbstractWizard):

    _logger = get_logger(__name__)

    def __init__(self, daemon: 'Daemon'):
        AbstractWizard.__init__(self)
        self.navmap = {
            'welcome': {
                'next': lambda d: 'proxy_config' if d['want_proxy'] else 'server_config',
                'accept': self.do_configure_autoconnect,
                'last': lambda d: bool(d['autoconnect'] and not d['want_proxy'])
            },
            'proxy_config': {
                'next': 'server_config',
                'accept': self.do_configure_proxy,
                'last': lambda d: bool(d['autoconnect'])
            },
            'server_config': {
                'accept': self.do_configure_server,
                'last': True
            }
        }
        self._daemon = daemon

    def do_configure_proxy(self, wizard_data: dict):
        proxy_settings = wizard_data['proxy']
        if not self._daemon.network:
            self._logger.debug('not configuring proxy, electrum config wants offline mode')
            return
        self._logger.debug(f'configuring proxy: {proxy_settings!r}')
        net_params = self._daemon.network.get_parameters()
        if not proxy_settings['enabled']:
            proxy_settings = None
        net_params = net_params._replace(proxy=proxy_settings, auto_connect=bool(wizard_data['autoconnect']))
        self._daemon.network.run_from_another_thread(self._daemon.network.set_parameters(net_params))

    def do_configure_server(self, wizard_data: dict):
        self._logger.debug(f'configuring server: {wizard_data!r}')
        net_params = self._daemon.network.get_parameters()
        server = ''
        if not wizard_data['autoconnect']:
            try:
                server = ServerAddr.from_str_with_inference(wizard_data['server'])
                if not server:
                    raise Exception('failed to parse server %s' % wizard_data['server'])
            except Exception:
                return
        net_params = net_params._replace(server=server, auto_connect=wizard_data['autoconnect'])
        self._daemon.network.run_from_another_thread(self._daemon.network.set_parameters(net_params))

    def do_configure_autoconnect(self, wizard_data: dict):
        self._logger.debug(f'configuring autoconnect: {wizard_data!r}')
        if self._daemon.config.cv.NETWORK_AUTO_CONNECT.is_modifiable():
            if wizard_data.get('autoconnect') is not None:
                self._daemon.config.NETWORK_AUTO_CONNECT = wizard_data.get('autoconnect')

    def start(self, initial_data: dict = None) -> WizardViewState:
        if initial_data is None:
            initial_data = {}
        self.reset()
        start_view = 'welcome'
        params = self.navmap[start_view].get('params', {})
        self._current = WizardViewState(start_view, initial_data, params)
        return self._current
