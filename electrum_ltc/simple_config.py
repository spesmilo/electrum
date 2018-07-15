import json
import threading
import time
import os
import stat
from decimal import Decimal
from typing import Union
from numbers import Real

from copy import deepcopy

from . import util
from .util import (user_dir, print_error, PrintError, make_dir,
                   NoDynamicFeeEstimates, format_fee_satoshis, quantize_feerate)
from .i18n import _

FEE_ETA_TARGETS = [25, 10, 5, 2]
FEE_DEPTH_TARGETS = [10000000, 5000000, 2000000, 1000000, 500000, 200000, 100000]

# satoshi per kbyte
FEERATE_MAX_DYNAMIC = 1000000
FEERATE_WARNING_HIGH_FEE = 600000
FEERATE_FALLBACK_STATIC_FEE = 100000
FEERATE_DEFAULT_RELAY = 1000
FEERATE_STATIC_VALUES = [10000, 20000, 30000, 50000, 70000, 100000, 150000, 200000, 300000, 500000]


config = None


def get_config():
    global config
    return config


def set_config(c):
    global config
    config = c


FINAL_CONFIG_VERSION = 3


class SimpleConfig(PrintError):
    """
    The SimpleConfig class is responsible for handling operations involving
    configuration files.

    There are two different sources of possible configuration values:
        1. Command line options.
        2. User configuration (in the user's config directory)
    They are taken in order (1. overrides config options set in 2.)
    """

    def __init__(self, options=None, read_user_config_function=None,
                 read_user_dir_function=None):

        if options is None:
            options = {}

        # This lock needs to be acquired for updating and reading the config in
        # a thread-safe way.
        self.lock = threading.RLock()

        self.mempool_fees = {}
        self.fee_estimates = {}
        self.fee_estimates_last_updated = {}
        self.last_time_fee_estimates_requested = 0  # zero ensures immediate fees

        # The following two functions are there for dependency injection when
        # testing.
        if read_user_config_function is None:
            read_user_config_function = read_user_config
        if read_user_dir_function is None:
            self.user_dir = user_dir
        else:
            self.user_dir = read_user_dir_function

        # The command line options
        self.cmdline_options = deepcopy(options)
        # don't allow to be set on CLI:
        self.cmdline_options.pop('config_version', None)

        # Set self.path and read the user config
        self.user_config = {}  # for self.get in electrum_path()
        self.path = self.electrum_path()
        self.user_config = read_user_config_function(self.path)
        if not self.user_config:
            # avoid new config getting upgraded
            self.user_config = {'config_version': FINAL_CONFIG_VERSION}

        # config "upgrade" - CLI options
        self.rename_config_keys(
            self.cmdline_options, {'auto_cycle': 'auto_connect'}, True)

        # config upgrade - user config
        if self.requires_upgrade():
            self.upgrade()

        # Make a singleton instance of 'self'
        set_config(self)

    def electrum_path(self):
        # Read electrum_path from command line
        # Otherwise use the user's default data directory.
        path = self.get('electrum_path')
        if path is None:
            path = self.user_dir()

        make_dir(path, allow_symlink=False)
        if self.get('testnet'):
            path = os.path.join(path, 'testnet')
            make_dir(path, allow_symlink=False)
        elif self.get('regtest'):
            path = os.path.join(path, 'regtest')
            make_dir(path, allow_symlink=False)
        elif self.get('simnet'):
            path = os.path.join(path, 'simnet')
            make_dir(path, allow_symlink=False)

        self.print_error("electrum directory", path)
        return path

    def rename_config_keys(self, config, keypairs, deprecation_warning=False):
        """Migrate old key names to new ones"""
        updated = False
        for old_key, new_key in keypairs.items():
            if old_key in config:
                if new_key not in config:
                    config[new_key] = config[old_key]
                    if deprecation_warning:
                        self.print_stderr('Note that the {} variable has been deprecated. '
                                     'You should use {} instead.'.format(old_key, new_key))
                del config[old_key]
                updated = True
        return updated

    def set_key(self, key, value, save=True):
        if not self.is_modifiable(key):
            self.print_stderr("Warning: not changing config key '%s' set on the command line" % key)
            return
        self._set_key_in_user_config(key, value, save)

    def _set_key_in_user_config(self, key, value, save=True):
        with self.lock:
            if value is not None:
                self.user_config[key] = value
            else:
                self.user_config.pop(key, None)
            if save:
                self.save_user_config()

    def get(self, key, default=None):
        with self.lock:
            out = self.cmdline_options.get(key)
            if out is None:
                out = self.user_config.get(key, default)
        return out

    def requires_upgrade(self):
        return self.get_config_version() < FINAL_CONFIG_VERSION

    def upgrade(self):
        with self.lock:
            self.print_error('upgrading config')

            self.convert_version_2()
            self.convert_version_3()

            self.set_key('config_version', FINAL_CONFIG_VERSION, save=True)

    def convert_version_2(self):
        if not self._is_upgrade_method_needed(1, 1):
            return

        self.rename_config_keys(self.user_config, {'auto_cycle': 'auto_connect'})

        try:
            # change server string FROM host:port:proto TO host:port:s
            server_str = self.user_config.get('server')
            host, port, protocol = str(server_str).rsplit(':', 2)
            assert protocol in ('s', 't')
            int(port)  # Throw if cannot be converted to int
            server_str = '{}:{}:s'.format(host, port)
            self._set_key_in_user_config('server', server_str)
        except BaseException:
            self._set_key_in_user_config('server', None)

        self.set_key('config_version', 2)

    def convert_version_3(self):
        if not self._is_upgrade_method_needed(2, 2):
            return

        base_unit = self.user_config.get('base_unit')
        if isinstance(base_unit, str):
            self._set_key_in_user_config('base_unit', None)
            map_ = {'ltc':8, 'mltc':5, 'ultc':2, 'bits':2, 'sat':0}
            decimal_point = map_.get(base_unit.lower())
            self._set_key_in_user_config('decimal_point', decimal_point)

        self.set_key('config_version', 3)

    def _is_upgrade_method_needed(self, min_version, max_version):
        cur_version = self.get_config_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise Exception(
                ('config upgrade: unexpected version %d (should be %d-%d)'
                 % (cur_version, min_version, max_version)))
        else:
            return True

    def get_config_version(self):
        config_version = self.get('config_version', 1)
        if config_version > FINAL_CONFIG_VERSION:
            self.print_stderr('WARNING: config version ({}) is higher than ours ({})'
                             .format(config_version, FINAL_CONFIG_VERSION))
        return config_version

    def is_modifiable(self, key):
        return key not in self.cmdline_options

    def save_user_config(self):
        if not self.path:
            return
        path = os.path.join(self.path, "config")
        s = json.dumps(self.user_config, indent=4, sort_keys=True)
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(s)
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        except FileNotFoundError:
            # datadir probably deleted while running...
            if os.path.exists(self.path):  # or maybe not?
                raise

    def get_wallet_path(self):
        """Set the path of the wallet."""

        # command line -w option
        if self.get('wallet_path'):
            return os.path.join(self.get('cwd'), self.get('wallet_path'))

        # path in config file
        path = self.get('default_wallet_path')
        if path and os.path.exists(path):
            return path

        # default path
        util.assert_datadir_available(self.path)
        dirpath = os.path.join(self.path, "wallets")
        make_dir(dirpath, allow_symlink=False)

        new_path = os.path.join(self.path, "wallets", "default_wallet")

        # default path in pre 1.9 versions
        old_path = os.path.join(self.path, "electrum-ltc.dat")
        if os.path.exists(old_path) and not os.path.exists(new_path):
            os.rename(old_path, new_path)

        return new_path

    def remove_from_recently_open(self, filename):
        recent = self.get('recently_open', [])
        if filename in recent:
            recent.remove(filename)
            self.set_key('recently_open', recent)

    def set_session_timeout(self, seconds):
        self.print_error("session timeout -> %d seconds" % seconds)
        self.set_key('session_timeout', seconds)

    def get_session_timeout(self):
        return self.get('session_timeout', 300)

    def open_last_wallet(self):
        if self.get('wallet_path') is None:
            last_wallet = self.get('gui_last_wallet')
            if last_wallet is not None and os.path.exists(last_wallet):
                self.cmdline_options['default_wallet_path'] = last_wallet

    def save_last_wallet(self, wallet):
        if self.get('wallet_path') is None:
            path = wallet.storage.path
            self.set_key('gui_last_wallet', path)

    def impose_hard_limits_on_fee(func):
        def get_fee_within_limits(self, *args, **kwargs):
            fee = func(self, *args, **kwargs)
            if fee is None:
                return fee
            fee = min(FEERATE_MAX_DYNAMIC, fee)
            fee = max(FEERATE_DEFAULT_RELAY, fee)
            return fee
        return get_fee_within_limits

    @impose_hard_limits_on_fee
    def eta_to_fee(self, slider_pos) -> Union[int, None]:
        """Returns fee in sat/kbyte."""
        slider_pos = max(slider_pos, 0)
        slider_pos = min(slider_pos, len(FEE_ETA_TARGETS))
        if slider_pos < len(FEE_ETA_TARGETS):
            target_blocks = FEE_ETA_TARGETS[slider_pos]
            fee = self.fee_estimates.get(target_blocks)
        else:
            fee = self.fee_estimates.get(2)
            if fee is not None:
                fee += fee/2
                fee = int(fee)
        return fee

    def fee_to_depth(self, target_fee: Real) -> int:
        """For a given sat/vbyte fee, returns an estimate of how deep
        it would be in the current mempool in vbytes.
        Pessimistic == overestimates the depth.
        """
        depth = 0
        for fee, s in self.mempool_fees:
            depth += s
            if fee <= target_fee:
                break
        return depth

    def depth_to_fee(self, slider_pos) -> int:
        """Returns fee in sat/kbyte."""
        target = self.depth_target(slider_pos)
        return self.depth_target_to_fee(target)

    @impose_hard_limits_on_fee
    def depth_target_to_fee(self, target: int) -> int:
        """Returns fee in sat/kbyte.
        target: desired mempool depth in vbytes
        """
        depth = 0
        for fee, s in self.mempool_fees:
            depth += s
            if depth > target:
                break
        else:
            return 0
        # add one sat/byte as currently that is
        # the max precision of the histogram
        fee += 1
        # convert to sat/kbyte
        return fee * 1000

    def depth_target(self, slider_pos):
        slider_pos = max(slider_pos, 0)
        slider_pos = min(slider_pos, len(FEE_DEPTH_TARGETS)-1)
        return FEE_DEPTH_TARGETS[slider_pos]

    def eta_target(self, i):
        if i == len(FEE_ETA_TARGETS):
            return 1
        return FEE_ETA_TARGETS[i]

    def fee_to_eta(self, fee_per_kb):
        import operator
        l = list(self.fee_estimates.items()) + [(1, self.eta_to_fee(4))]
        for i in range(len(l)-1, 0, -1):
            if l[i][1] == l[i-1][1]:
                del l[i-1]
        dist = map(lambda x: (x[0], abs(x[1] - fee_per_kb)), l)
        min_target, min_value = min(dist, key=operator.itemgetter(1))
        if fee_per_kb < self.fee_estimates.get(25)/2:
            min_target = -1
        return min_target

    def depth_tooltip(self, depth):
        return "%.1f MB from tip"%(depth/1000000)

    def eta_tooltip(self, x):
        if x < 0:
            return _('Low fee')
        elif x == 1:
            return _('In the next block')
        else:
            return _('Within {} blocks').format(x)

    def get_fee_status(self):
        dyn = self.is_dynfee()
        mempool = self.use_mempool_fees()
        pos = self.get_depth_level() if mempool else self.get_fee_level()
        fee_rate = self.fee_per_kb()
        target, tooltip = self.get_fee_text(pos, dyn, mempool, fee_rate)
        return tooltip + '  [%s]'%target if dyn else target + '  [Static]'

    def get_fee_text(self, pos, dyn, mempool, fee_rate):
        """Returns (text, tooltip) where
        text is what we target: static fee / num blocks to confirm in / mempool depth
        tooltip is the corresponding estimate (e.g. num blocks for a static fee)
        """
        if fee_rate is None:
            rate_str = 'unknown'
        else:
            rate_str = format_fee_satoshis(fee_rate/1000) + ' sat/byte'

        if dyn:
            if mempool:
                depth = self.depth_target(pos)
                text = self.depth_tooltip(depth)
            else:
                eta = self.eta_target(pos)
                text = self.eta_tooltip(eta)
            tooltip = rate_str
        else:
            text = rate_str
            if mempool and self.has_fee_mempool():
                depth = self.fee_to_depth(fee_rate)
                tooltip = self.depth_tooltip(depth)
            elif not mempool and self.has_fee_etas():
                eta = self.fee_to_eta(fee_rate)
                tooltip = self.eta_tooltip(eta)
            else:
                tooltip = ''
        return text, tooltip

    def get_depth_level(self):
        maxp = len(FEE_DEPTH_TARGETS) - 1
        return min(maxp, self.get('depth_level', 2))

    def get_fee_level(self):
        maxp = len(FEE_ETA_TARGETS)  # not (-1) to have "next block"
        return min(maxp, self.get('fee_level', 2))

    def get_fee_slider(self, dyn, mempool):
        if dyn:
            if mempool:
                pos = self.get_depth_level()
                maxp = len(FEE_DEPTH_TARGETS) - 1
                fee_rate = self.depth_to_fee(pos)
            else:
                pos = self.get_fee_level()
                maxp = len(FEE_ETA_TARGETS)  # not (-1) to have "next block"
                fee_rate = self.eta_to_fee(pos)
        else:
            fee_rate = self.fee_per_kb(dyn=False)
            pos = self.static_fee_index(fee_rate)
            maxp = 9
        return maxp, pos, fee_rate

    def static_fee(self, i):
        return FEERATE_STATIC_VALUES[i]

    def static_fee_index(self, value):
        if value is None:
            raise TypeError('static fee cannot be None')
        dist = list(map(lambda x: abs(x - value), FEERATE_STATIC_VALUES))
        return min(range(len(dist)), key=dist.__getitem__)

    def has_fee_etas(self):
        return len(self.fee_estimates) == 4

    def has_fee_mempool(self):
        return bool(self.mempool_fees)

    def has_dynamic_fees_ready(self):
        if self.use_mempool_fees():
            return self.has_fee_mempool()
        else:
            return self.has_fee_etas()

    def is_dynfee(self):
        return bool(self.get('dynamic_fees', False))

    def use_mempool_fees(self):
        return bool(self.get('mempool_fees', False))

    def _feerate_from_fractional_slider_position(self, fee_level: float, dyn: bool,
                                                 mempool: bool) -> Union[int, None]:
        fee_level = max(fee_level, 0)
        fee_level = min(fee_level, 1)
        if dyn:
            max_pos = (len(FEE_DEPTH_TARGETS) - 1) if mempool else len(FEE_ETA_TARGETS)
            slider_pos = round(fee_level * max_pos)
            fee_rate = self.depth_to_fee(slider_pos) if mempool else self.eta_to_fee(slider_pos)
        else:
            max_pos = len(FEERATE_STATIC_VALUES) - 1
            slider_pos = round(fee_level * max_pos)
            fee_rate = FEERATE_STATIC_VALUES[slider_pos]
        return fee_rate

    def fee_per_kb(self, dyn: bool=None, mempool: bool=None, fee_level: float=None) -> Union[int, None]:
        """Returns sat/kvB fee to pay for a txn.
        Note: might return None.

        fee_level: float between 0.0 and 1.0, representing fee slider position
        """
        if dyn is None:
            dyn = self.is_dynfee()
        if mempool is None:
            mempool = self.use_mempool_fees()
        if fee_level is not None:
            return self._feerate_from_fractional_slider_position(fee_level, dyn, mempool)
        # there is no fee_level specified; will use config.
        # note: 'depth_level' and 'fee_level' in config are integer slider positions,
        # unlike fee_level here, which (when given) is a float in [0.0, 1.0]
        if dyn:
            if mempool:
                fee_rate = self.depth_to_fee(self.get_depth_level())
            else:
                fee_rate = self.eta_to_fee(self.get_fee_level())
        else:
            fee_rate = self.get('fee_per_kb', FEERATE_FALLBACK_STATIC_FEE)
        return fee_rate

    def fee_per_byte(self):
        """Returns sat/vB fee to pay for a txn.
        Note: might return None.
        """
        fee_per_kb = self.fee_per_kb()
        return fee_per_kb / 1000 if fee_per_kb is not None else None

    def estimate_fee(self, size):
        fee_per_kb = self.fee_per_kb()
        if fee_per_kb is None:
            raise NoDynamicFeeEstimates()
        return self.estimate_fee_for_feerate(fee_per_kb, size)

    @classmethod
    def estimate_fee_for_feerate(cls, fee_per_kb, size):
        fee_per_kb = Decimal(fee_per_kb)
        fee_per_byte = fee_per_kb / 1000
        # to be consistent with what is displayed in the GUI,
        # the calculation needs to use the same precision:
        fee_per_byte = quantize_feerate(fee_per_byte)
        return round(fee_per_byte * size)

    def update_fee_estimates(self, key, value):
        self.fee_estimates[key] = value
        self.fee_estimates_last_updated[key] = time.time()

    def is_fee_estimates_update_required(self):
        """Checks time since last requested and updated fee estimates.
        Returns True if an update should be requested.
        """
        now = time.time()
        return now - self.last_time_fee_estimates_requested > 60

    def requested_fee_estimates(self):
        self.last_time_fee_estimates_requested = time.time()

    def get_video_device(self):
        device = self.get("video_device", "default")
        if device == 'default':
            device = ''
        return device


def read_user_config(path):
    """Parse and store the user config settings in electrum-ltc.conf into user_config[]."""
    if not path:
        return {}
    config_path = os.path.join(path, "config")
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding='utf-8') as f:
            data = f.read()
        result = json.loads(data)
    except:
        print_error("Warning: Cannot read config file.", config_path)
        return {}
    if not type(result) is dict:
        return {}
    return result
