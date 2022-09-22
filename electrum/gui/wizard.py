import copy

from typing import List, TYPE_CHECKING, Tuple, NamedTuple, Any, Dict, Optional, Union

from electrum.logging import get_logger

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
        return False # TODO: self._daemon.config.get('single_password')

    def last_if_single_password_and_not_bip39(self, view, wizard_data):
        return self.last_if_single_password(view, wizard_data) and not wizard_data['seed_type'] == 'bip39'

    def on_wallet_type(self, wizard_data):
        if wizard_data['wallet_type'] == '2fa':
            return 'trustedcoin_start'

        return 'keystore_type'

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
