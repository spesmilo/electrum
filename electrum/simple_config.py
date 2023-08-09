import json
import threading
import time
import os
import stat
import ssl
from decimal import Decimal
from typing import Union, Optional, Dict, Sequence, Tuple, Any, Set
from numbers import Real
from functools import cached_property

from copy import deepcopy
from aiorpcx import NetAddress

from . import util
from . import constants
from . import invoices
from .util import base_units, base_unit_name_to_decimal_point, decimal_point_to_base_unit_name, UnknownBaseUnit, DECIMAL_POINT_DEFAULT
from .util import format_satoshis, format_fee_satoshis, os_chmod
from .util import user_dir, make_dir, NoDynamicFeeEstimates, quantize_feerate
from .lnutil import LN_MAX_FUNDING_SAT_LEGACY
from .i18n import _
from .logging import get_logger, Logger


FEE_ETA_TARGETS = [25, 10, 5, 2]
FEE_DEPTH_TARGETS = [10_000_000, 5_000_000, 2_000_000, 1_000_000,
                     800_000, 600_000, 400_000, 250_000, 100_000]
FEE_LN_ETA_TARGET = 2  # note: make sure the network is asking for estimates for this target

# satoshi per kbyte
FEERATE_MAX_DYNAMIC = 1500000
FEERATE_WARNING_HIGH_FEE = 600000
FEERATE_FALLBACK_STATIC_FEE = 150000
FEERATE_DEFAULT_RELAY = 1000
FEERATE_MAX_RELAY = 50000
FEERATE_STATIC_VALUES = [1000, 2000, 5000, 10000, 20000, 30000,
                         50000, 70000, 100000, 150000, 200000, 300000]
FEERATE_REGTEST_HARDCODED = 180000  # for eclair compat

# The min feerate_per_kw that can be used in lightning so that
# the resulting onchain tx pays the min relay fee.
# This would be FEERATE_DEFAULT_RELAY / 4 if not for rounding errors,
# see https://github.com/ElementsProject/lightning/commit/2e687b9b352c9092b5e8bd4a688916ac50b44af0
FEERATE_PER_KW_MIN_RELAY_LIGHTNING = 253

FEE_RATIO_HIGH_WARNING = 0.05  # warn user if fee/amount for on-chain tx is higher than this


_logger = get_logger(__name__)


FINAL_CONFIG_VERSION = 3


class ConfigVar(property):

    def __init__(self, key: str, *, default, type_=None):
        self._key = key
        self._default = default
        self._type = type_
        property.__init__(self, self._get_config_value, self._set_config_value)

    def _get_config_value(self, config: 'SimpleConfig'):
        value = config.get(self._key, default=self._default)
        if self._type is not None and value != self._default:
            assert value is not None, f"got None for key={self._key!r}"
            try:
                value = self._type(value)
            except Exception as e:
                raise ValueError(
                    f"ConfigVar.get type-check and auto-conversion failed. "
                    f"key={self._key!r}. type={self._type}. value={value!r}") from e
        return value

    def _set_config_value(self, config: 'SimpleConfig', value, *, save=True):
        if self._type is not None and value is not None:
            if not isinstance(value, self._type):
                raise ValueError(
                    f"ConfigVar.set type-check failed. "
                    f"key={self._key!r}. type={self._type}. value={value!r}")
        config.set_key(self._key, value, save=save)

    def key(self) -> str:
        return self._key

    def get_default_value(self) -> Any:
        return self._default

    def __repr__(self):
        return f"<ConfigVar key={self._key!r}>"

    def __deepcopy__(self, memo):
        cv = ConfigVar(self._key, default=self._default, type_=self._type)
        return cv


class ConfigVarWithConfig:

    def __init__(self, *, config: 'SimpleConfig', config_var: 'ConfigVar'):
        self._config = config
        self._config_var = config_var

    def get(self) -> Any:
        return self._config_var._get_config_value(self._config)

    def set(self, value: Any, *, save=True) -> None:
        self._config_var._set_config_value(self._config, value, save=save)

    def key(self) -> str:
        return self._config_var.key()

    def get_default_value(self) -> Any:
        return self._config_var.get_default_value()

    def is_modifiable(self) -> bool:
        return self._config.is_modifiable(self._config_var)

    def is_set(self) -> bool:
        return self._config.is_set(self._config_var)

    def __repr__(self):
        return f"<ConfigVarWithConfig key={self.key()!r}>"


class SimpleConfig(Logger):
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

        Logger.__init__(self)

        # This lock needs to be acquired for updating and reading the config in
        # a thread-safe way.
        self.lock = threading.RLock()

        self.mempool_fees = None  # type: Optional[Sequence[Tuple[Union[float, int], int]]]
        self.fee_estimates = {}  # type: Dict[int, int]
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

        self._not_modifiable_keys = set()  # type: Set[str]

        # config "upgrade" - CLI options
        self.rename_config_keys(
            self.cmdline_options, {'auto_cycle': 'auto_connect'}, True)

        # config upgrade - user config
        if self.requires_upgrade():
            self.upgrade()

        self._check_dependent_keys()

        # units and formatting
        # FIXME is this duplication (dp, nz, post_sat, thou_sep) due to performance reasons??
        self.decimal_point = self.BTC_AMOUNTS_DECIMAL_POINT
        try:
            decimal_point_to_base_unit_name(self.decimal_point)
        except UnknownBaseUnit:
            self.decimal_point = DECIMAL_POINT_DEFAULT
        self.num_zeros = self.BTC_AMOUNTS_FORCE_NZEROS_AFTER_DECIMAL_POINT
        self.amt_precision_post_satoshi = self.BTC_AMOUNTS_PREC_POST_SAT
        self.amt_add_thousands_sep = self.BTC_AMOUNTS_ADD_THOUSANDS_SEP

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
        elif self.get('signet'):
            path = os.path.join(path, 'signet')
            make_dir(path, allow_symlink=False)

        self.logger.info(f"electrum directory {path}")
        return path

    def rename_config_keys(self, config, keypairs, deprecation_warning=False):
        """Migrate old key names to new ones"""
        updated = False
        for old_key, new_key in keypairs.items():
            if old_key in config:
                if new_key not in config:
                    config[new_key] = config[old_key]
                    if deprecation_warning:
                        self.logger.warning('Note that the {} variable has been deprecated. '
                                            'You should use {} instead.'.format(old_key, new_key))
                del config[old_key]
                updated = True
        return updated

    def set_key(self, key: Union[str, ConfigVar, ConfigVarWithConfig], value, *, save=True) -> None:
        """Set the value for an arbitrary string config key.
        note: try to use explicit predefined ConfigVars instead of this method, whenever possible.
              This method side-steps ConfigVars completely, and is mainly kept for situations
              where the config key is dynamically constructed.
        """
        if isinstance(key, (ConfigVar, ConfigVarWithConfig)):
            key = key.key()
        assert isinstance(key, str), key
        if not self.is_modifiable(key):
            self.logger.warning(f"not changing config key '{key}' set on the command line")
            return
        try:
            json.dumps(key)
            json.dumps(value)
        except Exception:
            self.logger.info(f"json error: cannot save {repr(key)} ({repr(value)})")
            return
        self._set_key_in_user_config(key, value, save=save)

    def _set_key_in_user_config(self, key: str, value, *, save=True) -> None:
        assert isinstance(key, str), key
        with self.lock:
            if value is not None:
                self.user_config[key] = value
            else:
                self.user_config.pop(key, None)
            if save:
                self.save_user_config()

    def get(self, key: str, default=None) -> Any:
        """Get the value for an arbitrary string config key.
        note: try to use explicit predefined ConfigVars instead of this method, whenever possible.
              This method side-steps ConfigVars completely, and is mainly kept for situations
              where the config key is dynamically constructed.
        """
        assert isinstance(key, str), key
        with self.lock:
            out = self.cmdline_options.get(key)
            if out is None:
                out = self.user_config.get(key, default)
        return out

    def is_set(self, key: Union[str, ConfigVar, ConfigVarWithConfig]) -> bool:
        """Returns whether the config key has any explicit value set/defined."""
        if isinstance(key, (ConfigVar, ConfigVarWithConfig)):
            key = key.key()
        assert isinstance(key, str), key
        return self.get(key, default=...) is not ...

    def _check_dependent_keys(self) -> None:
        if self.NETWORK_SERVERFINGERPRINT:
            if not self.NETWORK_SERVER:
                raise Exception(
                    f"config key {self.__class__.NETWORK_SERVERFINGERPRINT.key()!r} requires "
                    f"{self.__class__.NETWORK_SERVER.key()!r} to also be set")
            self.make_key_not_modifiable(self.__class__.NETWORK_SERVER)

    def requires_upgrade(self):
        return self.get_config_version() < FINAL_CONFIG_VERSION

    def upgrade(self):
        with self.lock:
            self.logger.info('upgrading config')

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
            map_ = {'btc':8, 'mbtc':5, 'ubtc':2, 'bits':2, 'sat':0}
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
            self.logger.warning('config version ({}) is higher than latest ({})'
                                .format(config_version, FINAL_CONFIG_VERSION))
        return config_version

    def is_modifiable(self, key: Union[str, ConfigVar, ConfigVarWithConfig]) -> bool:
        if isinstance(key, (ConfigVar, ConfigVarWithConfig)):
            key = key.key()
        return (key not in self.cmdline_options
                and key not in self._not_modifiable_keys)

    def make_key_not_modifiable(self, key: Union[str, ConfigVar, ConfigVarWithConfig]) -> None:
        if isinstance(key, (ConfigVar, ConfigVarWithConfig)):
            key = key.key()
        assert isinstance(key, str), key
        self._not_modifiable_keys.add(key)

    def save_user_config(self):
        if self.CONFIG_FORGET_CHANGES:
            return
        if not self.path:
            return
        path = os.path.join(self.path, "config")
        s = json.dumps(self.user_config, indent=4, sort_keys=True)
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(s)
            os_chmod(path, stat.S_IREAD | stat.S_IWRITE)
        except FileNotFoundError:
            # datadir probably deleted while running...
            if os.path.exists(self.path):  # or maybe not?
                raise

    def get_backup_dir(self) -> Optional[str]:
        # this is used to save wallet file backups (without active lightning channels)
        # on Android, the export backup button uses android_backup_dir()
        if 'ANDROID_DATA' in os.environ:
            return None
        else:
            return self.WALLET_BACKUP_DIRECTORY

    def get_wallet_path(self, *, use_gui_last_wallet=False):
        """Set the path of the wallet."""

        # command line -w option
        if self.get('wallet_path'):
            return os.path.join(self.get('cwd', ''), self.get('wallet_path'))

        if use_gui_last_wallet:
            path = self.GUI_LAST_WALLET
            if path and os.path.exists(path):
                return path

        new_path = self.get_fallback_wallet_path()

        # default path in pre 1.9 versions
        old_path = os.path.join(self.path, "electrum.dat")
        if os.path.exists(old_path) and not os.path.exists(new_path):
            os.rename(old_path, new_path)

        return new_path

    def get_fallback_wallet_path(self):
        util.assert_datadir_available(self.path)
        dirpath = os.path.join(self.path, "wallets")
        make_dir(dirpath, allow_symlink=False)
        path = os.path.join(self.path, "wallets", "default_wallet")
        return path

    def remove_from_recently_open(self, filename):
        recent = self.RECENTLY_OPEN_WALLET_FILES or []
        if filename in recent:
            recent.remove(filename)
            self.RECENTLY_OPEN_WALLET_FILES = recent

    def set_session_timeout(self, seconds):
        self.logger.info(f"session timeout -> {seconds} seconds")
        self.HWD_SESSION_TIMEOUT = seconds

    def get_session_timeout(self):
        return self.HWD_SESSION_TIMEOUT

    def save_last_wallet(self, wallet):
        if self.get('wallet_path') is None:
            path = wallet.storage.path
            self.GUI_LAST_WALLET = path

    def impose_hard_limits_on_fee(func):
        def get_fee_within_limits(self, *args, **kwargs):
            fee = func(self, *args, **kwargs)
            if fee is None:
                return fee
            fee = min(FEERATE_MAX_DYNAMIC, fee)
            fee = max(FEERATE_DEFAULT_RELAY, fee)
            return fee
        return get_fee_within_limits

    def eta_to_fee(self, slider_pos) -> Optional[int]:
        """Returns fee in sat/kbyte."""
        slider_pos = max(slider_pos, 0)
        slider_pos = min(slider_pos, len(FEE_ETA_TARGETS))
        if slider_pos < len(FEE_ETA_TARGETS):
            num_blocks = FEE_ETA_TARGETS[int(slider_pos)]
            fee = self.eta_target_to_fee(num_blocks)
        else:
            fee = self.eta_target_to_fee(1)
        return fee

    @impose_hard_limits_on_fee
    def eta_target_to_fee(self, num_blocks: int) -> Optional[int]:
        """Returns fee in sat/kbyte."""
        if num_blocks == 1:
            fee = self.fee_estimates.get(2)
            if fee is not None:
                fee += fee / 2
                fee = int(fee)
        else:
            fee = self.fee_estimates.get(num_blocks)
            if fee is not None:
                fee = int(fee)
        return fee

    def fee_to_depth(self, target_fee: Real) -> Optional[int]:
        """For a given sat/vbyte fee, returns an estimate of how deep
        it would be in the current mempool in vbytes.
        Pessimistic == overestimates the depth.
        """
        if self.mempool_fees is None:
            return None
        depth = 0
        for fee, s in self.mempool_fees:
            depth += s
            if fee <= target_fee:
                break
        return depth

    def depth_to_fee(self, slider_pos) -> Optional[int]:
        """Returns fee in sat/kbyte."""
        target = self.depth_target(slider_pos)
        return self.depth_target_to_fee(target)

    @impose_hard_limits_on_fee
    def depth_target_to_fee(self, target: int) -> Optional[int]:
        """Returns fee in sat/kbyte.
        target: desired mempool depth in vbytes
        """
        if self.mempool_fees is None:
            return None
        depth = 0
        for fee, s in self.mempool_fees:
            depth += s
            if depth > target:
                break
        else:
            return 0
        # add one sat/byte as currently that is the max precision of the histogram
        # note: precision depends on server.
        #       old ElectrumX <1.16 has 1 s/b prec, >=1.16 has 0.1 s/b prec.
        #       electrs seems to use untruncated double-precision floating points.
        #       # TODO decrease this to 0.1 s/b next time we bump the required protocol version
        fee += 1
        # convert to sat/kbyte
        return int(fee * 1000)

    def depth_target(self, slider_pos: int) -> int:
        """Returns mempool depth target in bytes for a fee slider position."""
        slider_pos = max(slider_pos, 0)
        slider_pos = min(slider_pos, len(FEE_DEPTH_TARGETS)-1)
        return FEE_DEPTH_TARGETS[slider_pos]

    def eta_target(self, slider_pos: int) -> int:
        """Returns 'num blocks' ETA target for a fee slider position."""
        if slider_pos == len(FEE_ETA_TARGETS):
            return 1
        return FEE_ETA_TARGETS[slider_pos]

    def fee_to_eta(self, fee_per_kb: Optional[int]) -> int:
        """Returns 'num blocks' ETA estimate for given fee rate,
        or -1 for low fee.
        """
        import operator
        lst = list(self.fee_estimates.items())
        next_block_fee = self.eta_target_to_fee(1)
        if next_block_fee is not None:
            lst += [(1, next_block_fee)]
        if not lst or fee_per_kb is None:
            return -1
        dist = map(lambda x: (x[0], abs(x[1] - fee_per_kb)), lst)
        min_target, min_value = min(dist, key=operator.itemgetter(1))
        if fee_per_kb < self.fee_estimates.get(FEE_ETA_TARGETS[0])/2:
            min_target = -1
        return min_target

    def get_depth_mb_str(self, depth: int) -> str:
        # e.g. 500_000 -> "0.50 MB"
        depth_mb = "{:.2f}".format(depth / 1_000_000)  # maybe .rstrip("0") ?
        return f"{depth_mb} MB"

    def depth_tooltip(self, depth: Optional[int]) -> str:
        """Returns text tooltip for given mempool depth (in vbytes)."""
        if depth is None:
            return "unknown from tip"
        depth_mb = self.get_depth_mb_str(depth)
        return _("{} from tip").format(depth_mb)

    def eta_tooltip(self, x):
        if x < 0:
            return _('Low fee')
        elif x == 1:
            return _('In the next block')
        else:
            return _('Within {} blocks').format(x)

    def get_fee_target(self):
        dyn = self.is_dynfee()
        mempool = self.use_mempool_fees()
        pos = self.get_depth_level() if mempool else self.get_fee_level()
        fee_rate = self.fee_per_kb()
        target, tooltip = self.get_fee_text(pos, dyn, mempool, fee_rate)
        return target, tooltip, dyn

    def get_fee_status(self):
        target, tooltip, dyn = self.get_fee_target()
        return tooltip + '  [%s]'%target if dyn else target + '  [Static]'

    def get_fee_text(
            self,
            slider_pos: int,
            dyn: bool,
            mempool: bool,
            fee_per_kb: Optional[int],
    ):
        """Returns (text, tooltip) where
        text is what we target: static fee / num blocks to confirm in / mempool depth
        tooltip is the corresponding estimate (e.g. num blocks for a static fee)

        fee_rate is in sat/kbyte
        """
        if fee_per_kb is None:
            rate_str = 'unknown'
            fee_per_byte = None
        else:
            fee_per_byte = fee_per_kb/1000
            rate_str = format_fee_satoshis(fee_per_byte) + ' sat/byte'

        if dyn:
            if mempool:
                depth = self.depth_target(slider_pos)
                text = self.depth_tooltip(depth)
            else:
                eta = self.eta_target(slider_pos)
                text = self.eta_tooltip(eta)
            tooltip = rate_str
        else:  # using static fees
            assert fee_per_kb is not None
            assert fee_per_byte is not None
            text = rate_str
            if mempool and self.has_fee_mempool():
                depth = self.fee_to_depth(fee_per_byte)
                tooltip = self.depth_tooltip(depth)
            elif not mempool and self.has_fee_etas():
                eta = self.fee_to_eta(fee_per_kb)
                tooltip = self.eta_tooltip(eta)
            else:
                tooltip = ''
        return text, tooltip

    def get_depth_level(self) -> int:
        maxp = len(FEE_DEPTH_TARGETS) - 1
        return min(maxp, self.FEE_EST_DYNAMIC_MEMPOOL_SLIDERPOS)

    def get_fee_level(self) -> int:
        maxp = len(FEE_ETA_TARGETS)  # not (-1) to have "next block"
        return min(maxp, self.FEE_EST_DYNAMIC_ETA_SLIDERPOS)

    def get_fee_slider(self, dyn, mempool) -> Tuple[int, int, Optional[int]]:
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
            maxp = len(FEERATE_STATIC_VALUES) - 1
        return maxp, pos, fee_rate

    def static_fee(self, i):
        return FEERATE_STATIC_VALUES[i]

    def static_fee_index(self, fee_per_kb: Optional[int]) -> int:
        if fee_per_kb is None:
            raise TypeError('static fee cannot be None')
        dist = list(map(lambda x: abs(x - fee_per_kb), FEERATE_STATIC_VALUES))
        return min(range(len(dist)), key=dist.__getitem__)

    def has_fee_etas(self):
        return len(self.fee_estimates) == 4

    def has_fee_mempool(self) -> bool:
        return self.mempool_fees is not None

    def has_dynamic_fees_ready(self):
        if self.use_mempool_fees():
            return self.has_fee_mempool()
        else:
            return self.has_fee_etas()

    def is_dynfee(self) -> bool:
        return self.FEE_EST_DYNAMIC

    def use_mempool_fees(self) -> bool:
        return self.FEE_EST_USE_MEMPOOL

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

    def fee_per_kb(self, dyn: bool=None, mempool: bool=None, fee_level: float=None) -> Optional[int]:
        """Returns sat/kvB fee to pay for a txn.
        Note: might return None.

        fee_level: float between 0.0 and 1.0, representing fee slider position
        """
        if constants.net is constants.BitcoinRegtest:
            return FEERATE_REGTEST_HARDCODED
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
            fee_rate = self.FEE_EST_STATIC_FEERATE_FALLBACK
        if fee_rate is not None:
            fee_rate = int(fee_rate)
        return fee_rate

    def fee_per_byte(self):
        """Returns sat/vB fee to pay for a txn.
        Note: might return None.
        """
        fee_per_kb = self.fee_per_kb()
        return fee_per_kb / 1000 if fee_per_kb is not None else None

    def estimate_fee(self, size: Union[int, float, Decimal], *,
                     allow_fallback_to_static_rates: bool = False) -> int:
        fee_per_kb = self.fee_per_kb()
        if fee_per_kb is None:
            if allow_fallback_to_static_rates:
                fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
            else:
                raise NoDynamicFeeEstimates()
        return self.estimate_fee_for_feerate(fee_per_kb, size)

    @classmethod
    def estimate_fee_for_feerate(cls, fee_per_kb: Union[int, float, Decimal],
                                 size: Union[int, float, Decimal]) -> int:
        size = Decimal(size)
        fee_per_kb = Decimal(fee_per_kb)
        fee_per_byte = fee_per_kb / 1000
        # to be consistent with what is displayed in the GUI,
        # the calculation needs to use the same precision:
        fee_per_byte = quantize_feerate(fee_per_byte)
        return round(fee_per_byte * size)

    def update_fee_estimates(self, nblock_target: int, fee_per_kb: int):
        assert isinstance(nblock_target, int), f"expected int, got {nblock_target!r}"
        assert isinstance(fee_per_kb, int), f"expected int, got {fee_per_kb!r}"
        self.fee_estimates[nblock_target] = fee_per_kb

    def is_fee_estimates_update_required(self):
        """Checks time since last requested and updated fee estimates.
        Returns True if an update should be requested.
        """
        now = time.time()
        return now - self.last_time_fee_estimates_requested > 60

    def requested_fee_estimates(self):
        self.last_time_fee_estimates_requested = time.time()

    def get_video_device(self):
        device = self.VIDEO_DEVICE_PATH
        if device == 'default':
            device = ''
        return device

    def get_ssl_context(self):
        ssl_keyfile = self.SSL_KEYFILE_PATH
        ssl_certfile = self.SSL_CERTFILE_PATH
        if ssl_keyfile and ssl_certfile:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(ssl_certfile, ssl_keyfile)
            return ssl_context

    def get_ssl_domain(self):
        from .paymentrequest import check_ssl_config
        if self.SSL_KEYFILE_PATH and self.SSL_CERTFILE_PATH:
            SSL_identity = check_ssl_config(self)
        else:
            SSL_identity = None
        return SSL_identity

    def get_netaddress(self, key: Union[str, ConfigVar, ConfigVarWithConfig]) -> Optional[NetAddress]:
        if isinstance(key, (ConfigVar, ConfigVarWithConfig)):
            key = key.key()
        assert isinstance(key, str), key
        text = self.get(key)
        if text:
            try:
                return NetAddress.from_string(text)
            except Exception:
                pass

    def format_amount(
        self,
        amount_sat,
        *,
        is_diff=False,
        whitespaces=False,
        precision=None,
        add_thousands_sep: bool = None,
    ) -> str:
        if precision is None:
            precision = self.amt_precision_post_satoshi
        if add_thousands_sep is None:
            add_thousands_sep = self.amt_add_thousands_sep
        return format_satoshis(
            amount_sat,
            num_zeros=self.num_zeros,
            decimal_point=self.decimal_point,
            is_diff=is_diff,
            whitespaces=whitespaces,
            precision=precision,
            add_thousands_sep=add_thousands_sep,
        )

    def format_amount_and_units(self, *args, **kwargs) -> str:
        return self.format_amount(*args, **kwargs) + ' ' + self.get_base_unit()

    def format_fee_rate(self, fee_rate):
        return format_fee_satoshis(fee_rate/1000, num_zeros=self.num_zeros) + ' sat/byte'

    def get_base_unit(self):
        return decimal_point_to_base_unit_name(self.decimal_point)

    def set_base_unit(self, unit):
        assert unit in base_units.keys()
        self.decimal_point = base_unit_name_to_decimal_point(unit)
        self.BTC_AMOUNTS_DECIMAL_POINT = self.decimal_point

    def get_decimal_point(self):
        return self.decimal_point

    @cached_property
    def cv(config):
        """Allows getting a reference to a config variable without dereferencing it.

        Compare:
        >>> config.NETWORK_SERVER
        'testnet.hsmiths.com:53012:s'
        >>> config.cv.NETWORK_SERVER
        <ConfigVarWithConfig key='server'>
        """
        class CVLookupHelper:
            def __getattribute__(self, name: str) -> ConfigVarWithConfig:
                config_var = config.__class__.__getattribute__(type(config), name)
                if not isinstance(config_var, ConfigVar):
                    raise AttributeError()
                return ConfigVarWithConfig(config=config, config_var=config_var)
            def __setattr__(self, name, value):
                raise Exception(
                    f"Cannot assign value to config.cv.{name} directly. "
                    f"Either use config.cv.{name}.set() or assign to config.{name} instead.")
        return CVLookupHelper()

    def get_swapserver_url(self):
        if constants.net == constants.BitcoinMainnet:
            return self.SWAPSERVER_URL_MAINNET
        elif constants.net == constants.BitcoinTestnet:
            return self.SWAPSERVER_URL_TESTNET
        else:
            return self.SWAPSERVER_URL_REGTEST

    # config variables ----->
    NETWORK_AUTO_CONNECT = ConfigVar('auto_connect', default=True, type_=bool)
    NETWORK_ONESERVER = ConfigVar('oneserver', default=False, type_=bool)
    NETWORK_PROXY = ConfigVar('proxy', default=None)
    NETWORK_SERVER = ConfigVar('server', default=None, type_=str)
    NETWORK_NOONION = ConfigVar('noonion', default=False, type_=bool)
    NETWORK_OFFLINE = ConfigVar('offline', default=False, type_=bool)
    NETWORK_SKIPMERKLECHECK = ConfigVar('skipmerklecheck', default=False, type_=bool)
    NETWORK_SERVERFINGERPRINT = ConfigVar('serverfingerprint', default=None, type_=str)
    NETWORK_MAX_INCOMING_MSG_SIZE = ConfigVar('network_max_incoming_msg_size', default=1_000_000, type_=int)  # in bytes
    NETWORK_TIMEOUT = ConfigVar('network_timeout', default=None, type_=int)

    WALLET_BATCH_RBF = ConfigVar('batch_rbf', default=False, type_=bool)
    WALLET_SPEND_CONFIRMED_ONLY = ConfigVar('confirmed_only', default=False, type_=bool)
    WALLET_COIN_CHOOSER_POLICY = ConfigVar('coin_chooser', default='Privacy', type_=str)
    WALLET_COIN_CHOOSER_OUTPUT_ROUNDING = ConfigVar('coin_chooser_output_rounding', default=True, type_=bool)
    WALLET_UNCONF_UTXO_FREEZE_THRESHOLD_SAT = ConfigVar('unconf_utxo_freeze_threshold', default=5_000, type_=int)
    WALLET_BIP21_LIGHTNING = ConfigVar('bip21_lightning', default=False, type_=bool)
    WALLET_BOLT11_FALLBACK = ConfigVar('bolt11_fallback', default=True, type_=bool)
    WALLET_PAYREQ_EXPIRY_SECONDS = ConfigVar('request_expiry', default=invoices.PR_DEFAULT_EXPIRATION_WHEN_CREATING, type_=int)
    WALLET_USE_SINGLE_PASSWORD = ConfigVar('single_password', default=False, type_=bool)
    # note: 'use_change' and 'multiple_change' are per-wallet settings

    FX_USE_EXCHANGE_RATE = ConfigVar('use_exchange_rate', default=False, type_=bool)
    FX_CURRENCY = ConfigVar('currency', default='EUR', type_=str)
    FX_EXCHANGE = ConfigVar('use_exchange', default='CoinGecko', type_=str)  # default exchange should ideally provide historical rates
    FX_HISTORY_RATES = ConfigVar('history_rates', default=False, type_=bool)
    FX_HISTORY_RATES_CAPITAL_GAINS = ConfigVar('history_rates_capital_gains', default=False, type_=bool)
    FX_SHOW_FIAT_BALANCE_FOR_ADDRESSES = ConfigVar('fiat_address', default=False, type_=bool)

    LIGHTNING_LISTEN = ConfigVar('lightning_listen', default=None, type_=str)
    LIGHTNING_PEERS = ConfigVar('lightning_peers', default=None)
    LIGHTNING_USE_GOSSIP = ConfigVar('use_gossip', default=False, type_=bool)
    LIGHTNING_USE_RECOVERABLE_CHANNELS = ConfigVar('use_recoverable_channels', default=True, type_=bool)
    LIGHTNING_ALLOW_INSTANT_SWAPS = ConfigVar('allow_instant_swaps', default=False, type_=bool)
    LIGHTNING_TO_SELF_DELAY_CSV = ConfigVar('lightning_to_self_delay', default=7 * 144, type_=int)
    LIGHTNING_MAX_FUNDING_SAT = ConfigVar('lightning_max_funding_sat', default=LN_MAX_FUNDING_SAT_LEGACY, type_=int)

    EXPERIMENTAL_LN_FORWARD_PAYMENTS = ConfigVar('lightning_forward_payments', default=False, type_=bool)
    EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = ConfigVar('lightning_forward_trampoline_payments', default=False, type_=bool)
    TEST_FAIL_HTLCS_WITH_TEMP_NODE_FAILURE = ConfigVar('test_fail_htlcs_with_temp_node_failure', default=False, type_=bool)
    TEST_FAIL_HTLCS_AS_MALFORMED = ConfigVar('test_fail_malformed_htlc', default=False, type_=bool)
    TEST_FORCE_MPP = ConfigVar('test_force_mpp', default=False, type_=bool)
    TEST_SHUTDOWN_FEE = ConfigVar('test_shutdown_fee', default=None, type_=int)
    TEST_SHUTDOWN_FEE_RANGE = ConfigVar('test_shutdown_fee_range', default=None)
    TEST_SHUTDOWN_LEGACY = ConfigVar('test_shutdown_legacy', default=False, type_=bool)

    FEE_EST_DYNAMIC = ConfigVar('dynamic_fees', default=True, type_=bool)
    FEE_EST_USE_MEMPOOL = ConfigVar('mempool_fees', default=False, type_=bool)
    FEE_EST_STATIC_FEERATE_FALLBACK = ConfigVar('fee_per_kb', default=FEERATE_FALLBACK_STATIC_FEE, type_=int)
    FEE_EST_DYNAMIC_ETA_SLIDERPOS = ConfigVar('fee_level', default=2, type_=int)
    FEE_EST_DYNAMIC_MEMPOOL_SLIDERPOS = ConfigVar('depth_level', default=2, type_=int)

    RPC_USERNAME = ConfigVar('rpcuser', default=None, type_=str)
    RPC_PASSWORD = ConfigVar('rpcpassword', default=None, type_=str)
    RPC_HOST = ConfigVar('rpchost', default='127.0.0.1', type_=str)
    RPC_PORT = ConfigVar('rpcport', default=0, type_=int)
    RPC_SOCKET_TYPE = ConfigVar('rpcsock', default='auto', type_=str)
    RPC_SOCKET_FILEPATH = ConfigVar('rpcsockpath', default=None, type_=str)

    GUI_NAME = ConfigVar('gui', default='qt', type_=str)
    GUI_LAST_WALLET = ConfigVar('gui_last_wallet', default=None, type_=str)

    GUI_QT_COLOR_THEME = ConfigVar('qt_gui_color_theme', default='default', type_=str)
    GUI_QT_DARK_TRAY_ICON = ConfigVar('dark_icon', default=False, type_=bool)
    GUI_QT_WINDOW_IS_MAXIMIZED = ConfigVar('is_maximized', default=False, type_=bool)
    GUI_QT_HIDE_ON_STARTUP = ConfigVar('hide_gui', default=False, type_=bool)
    GUI_QT_HISTORY_TAB_SHOW_TOOLBAR = ConfigVar('show_toolbar_history', default=False, type_=bool)
    GUI_QT_ADDRESSES_TAB_SHOW_TOOLBAR = ConfigVar('show_toolbar_addresses', default=False, type_=bool)
    GUI_QT_TX_DIALOG_FETCH_TXIN_DATA = ConfigVar('tx_dialog_fetch_txin_data', default=False, type_=bool)
    GUI_QT_RECEIVE_TABS_INDEX = ConfigVar('receive_tabs_index', default=0, type_=int)
    GUI_QT_RECEIVE_TAB_QR_VISIBLE = ConfigVar('receive_qr_visible', default=False, type_=bool)
    GUI_QT_TX_EDITOR_SHOW_IO = ConfigVar('show_tx_io', default=False, type_=bool)
    GUI_QT_TX_EDITOR_SHOW_FEE_DETAILS = ConfigVar('show_tx_fee_details', default=False, type_=bool)
    GUI_QT_TX_EDITOR_SHOW_LOCKTIME = ConfigVar('show_tx_locktime', default=False, type_=bool)
    GUI_QT_SHOW_TAB_ADDRESSES = ConfigVar('show_addresses_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_CHANNELS = ConfigVar('show_channels_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_UTXO = ConfigVar('show_utxo_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_CONTACTS = ConfigVar('show_contacts_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_CONSOLE = ConfigVar('show_console_tab', default=False, type_=bool)

    GUI_QML_PREFERRED_REQUEST_TYPE = ConfigVar('preferred_request_type', default='bolt11', type_=str)
    GUI_QML_USER_KNOWS_PRESS_AND_HOLD = ConfigVar('user_knows_press_and_hold', default=False, type_=bool)

    BTC_AMOUNTS_DECIMAL_POINT = ConfigVar('decimal_point', default=DECIMAL_POINT_DEFAULT, type_=int)
    BTC_AMOUNTS_FORCE_NZEROS_AFTER_DECIMAL_POINT = ConfigVar('num_zeros', default=0, type_=int)
    BTC_AMOUNTS_PREC_POST_SAT = ConfigVar('amt_precision_post_satoshi', default=0, type_=int)
    BTC_AMOUNTS_ADD_THOUSANDS_SEP = ConfigVar('amt_add_thousands_sep', default=False, type_=bool)

    BLOCK_EXPLORER = ConfigVar('block_explorer', default='Blockstream.info', type_=str)
    BLOCK_EXPLORER_CUSTOM = ConfigVar('block_explorer_custom', default=None)
    VIDEO_DEVICE_PATH = ConfigVar('video_device', default='default', type_=str)
    OPENALIAS_ID = ConfigVar('alias', default="", type_=str)
    HWD_SESSION_TIMEOUT = ConfigVar('session_timeout', default=300, type_=int)
    CLI_TIMEOUT = ConfigVar('timeout', default=60, type_=float)
    AUTOMATIC_CENTRALIZED_UPDATE_CHECKS = ConfigVar('check_updates', default=False, type_=bool)
    WRITE_LOGS_TO_DISK = ConfigVar('log_to_file', default=False, type_=bool)
    GUI_ENABLE_DEBUG_LOGS = ConfigVar('gui_enable_debug_logs', default=False, type_=bool)
    LOCALIZATION_LANGUAGE = ConfigVar('language', default="", type_=str)
    BLOCKCHAIN_PREFERRED_BLOCK = ConfigVar('blockchain_preferred_block', default=None)
    SHOW_CRASH_REPORTER = ConfigVar('show_crash_reporter', default=True, type_=bool)
    DONT_SHOW_TESTNET_WARNING = ConfigVar('dont_show_testnet_warning', default=False, type_=bool)
    RECENTLY_OPEN_WALLET_FILES = ConfigVar('recently_open', default=None)
    IO_DIRECTORY = ConfigVar('io_dir', default=os.path.expanduser('~'), type_=str)
    WALLET_BACKUP_DIRECTORY = ConfigVar('backup_dir', default=None, type_=str)
    CONFIG_PIN_CODE = ConfigVar('pin_code', default=None, type_=str)
    QR_READER_FLIP_X = ConfigVar('qrreader_flip_x', default=True, type_=bool)
    WIZARD_DONT_CREATE_SEGWIT = ConfigVar('nosegwit', default=False, type_=bool)
    CONFIG_FORGET_CHANGES = ConfigVar('forget_config', default=False, type_=bool)

    SSL_CERTFILE_PATH = ConfigVar('ssl_certfile', default='', type_=str)
    SSL_KEYFILE_PATH = ConfigVar('ssl_keyfile', default='', type_=str)
    # submarine swap server
    SWAPSERVER_URL_MAINNET = ConfigVar('swapserver_url_mainnet', default='https://swaps.electrum.org/api', type_=str)
    SWAPSERVER_URL_TESTNET = ConfigVar('swapserver_url_testnet', default='https://swaps.electrum.org/testnet', type_=str)
    SWAPSERVER_URL_REGTEST = ConfigVar('swapserver_url_regtest', default='http://localhost:5455/api', type_=str)
    TEST_SWAPSERVER_REFUND = ConfigVar('test_swapserver_refund', default=False, type_=bool)
    # connect to remote WT
    WATCHTOWER_CLIENT_ENABLED = ConfigVar('use_watchtower', default=False, type_=bool)
    WATCHTOWER_CLIENT_URL = ConfigVar('watchtower_url', default=None, type_=str)

    # run WT locally
    WATCHTOWER_SERVER_ENABLED = ConfigVar('run_watchtower', default=False, type_=bool)
    WATCHTOWER_SERVER_ADDRESS = ConfigVar('watchtower_address', default=None, type_=str)
    WATCHTOWER_SERVER_USER = ConfigVar('watchtower_user', default=None, type_=str)
    WATCHTOWER_SERVER_PASSWORD = ConfigVar('watchtower_password', default=None, type_=str)

    PAYSERVER_ADDRESS = ConfigVar('payserver_address', default='localhost:8080', type_=str)
    PAYSERVER_ROOT = ConfigVar('payserver_root', default='/r', type_=str)
    PAYSERVER_ALLOW_CREATE_INVOICE = ConfigVar('payserver_allow_create_invoice', default=False, type_=bool)

    SWAPSERVER_ADDRESS = ConfigVar('swapserver_address', default='localhost:5455', type_=str)

    PLUGIN_TRUSTEDCOIN_NUM_PREPAY = ConfigVar('trustedcoin_prepay', default=20, type_=int)


def read_user_config(path: Optional[str]) -> Dict[str, Any]:
    """Parse and store the user config settings in electrum.conf into user_config[]."""
    if not path:
        return {}
    config_path = os.path.join(path, "config")
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding='utf-8') as f:
            data = f.read()
        result = json.loads(data)
    except Exception as exc:
        _logger.warning(f"Cannot read config file at {config_path}: {exc}")
        return {}
    if not type(result) is dict:
        return {}
    return result
