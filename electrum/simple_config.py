import json
import threading
import time
import os
import stat
from decimal import Decimal
from typing import Union, Optional, Dict, Sequence, Tuple, Any, Set, Callable
from numbers import Real
from functools import cached_property

from copy import deepcopy

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
FEE_LN_ETA_TARGET = 2       # note: make sure the network is asking for estimates for this target
FEE_LN_LOW_ETA_TARGET = 25  # note: make sure the network is asking for estimates for this target

# satoshi per kbyte
FEERATE_MAX_DYNAMIC = 1500000
FEERATE_WARNING_HIGH_FEE = 600000
FEERATE_FALLBACK_STATIC_FEE = 150000
FEERATE_DEFAULT_RELAY = 1000
FEERATE_MAX_RELAY = 50000
FEERATE_STATIC_VALUES = [1000, 2000, 5000, 10000, 20000, 30000,
                         50000, 70000, 100000, 150000, 200000, 300000]

# The min feerate_per_kw that can be used in lightning so that
# the resulting onchain tx pays the min relay fee.
# This would be FEERATE_DEFAULT_RELAY / 4 if not for rounding errors,
# see https://github.com/ElementsProject/lightning/commit/2e687b9b352c9092b5e8bd4a688916ac50b44af0
FEERATE_PER_KW_MIN_RELAY_LIGHTNING = 253

FEE_RATIO_HIGH_WARNING = 0.05  # warn user if fee/amount for on-chain tx is higher than this



_logger = get_logger(__name__)


FINAL_CONFIG_VERSION = 3


_config_var_from_key = {}  # type: Dict[str, 'ConfigVar']


class ConfigVar(property):

    def __init__(
        self,
        key: str,
        *,
        default: Union[Any, Callable[['SimpleConfig'], Any]],  # typically a literal, but can also be a callable
        type_=None,
        convert_getter: Callable[[Any], Any] = None,
        short_desc: Callable[[], str] = None,
        long_desc: Callable[[], str] = None,
    ):
        self._key = key
        self._default = default
        self._type = type_
        self._convert_getter = convert_getter
        # note: the descriptions are callables instead of str literals, to delay evaluating the _() translations
        #       until after the language is set.
        assert short_desc is None or callable(short_desc)
        assert long_desc is None or callable(long_desc)
        self._short_desc = short_desc
        self._long_desc = long_desc
        property.__init__(self, self._get_config_value, self._set_config_value)
        assert key not in _config_var_from_key, f"duplicate config key str: {key!r}"
        _config_var_from_key[key] = self

    def _get_config_value(self, config: 'SimpleConfig'):
        with config.lock:
            if config.is_set(self._key):
                value = config.get(self._key)
                # run converter
                if self._convert_getter is not None:
                    value = self._convert_getter(value)
                # type-check
                if self._type is not None:
                    assert value is not None, f"got None for key={self._key!r}"
                    try:
                        value = self._type(value)
                    except Exception as e:
                        raise ValueError(
                            f"ConfigVar.get type-check and auto-conversion failed. "
                            f"key={self._key!r}. type={self._type}. value={value!r}") from e
            else:
                d = self._default
                value = d(config) if callable(d) else d
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

    def get_short_desc(self) -> Optional[str]:
        desc = self._short_desc
        return desc() if desc else None

    def get_long_desc(self) -> Optional[str]:
        desc = self._long_desc
        return desc() if desc else None

    def __repr__(self):
        return f"<ConfigVar key={self._key!r}>"

    def __deepcopy__(self, memo):
        # We can be considered ~stateless. State is stored in the config, which is external.
        return self


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

    def get_short_desc(self) -> Optional[str]:
        return self._config_var.get_short_desc()

    def get_long_desc(self) -> Optional[str]:
        return self._config_var.get_long_desc()

    def is_modifiable(self) -> bool:
        return self._config.is_modifiable(self._config_var)

    def is_set(self) -> bool:
        return self._config.is_set(self._config_var)

    def __repr__(self):
        return f"<ConfigVarWithConfig key={self.key()!r}>"

    def __eq__(self, other) -> bool:
        if not isinstance(other, ConfigVarWithConfig):
            return False
        return self._config is other._config and self._config_var is other._config_var


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

    def electrum_path_root(self):
        # Read electrum_path from command line
        # Otherwise use the user's default data directory.
        path = self.get('electrum_path') or self.user_dir()
        make_dir(path, allow_symlink=False)
        return path

    def electrum_path(self):
        path = self.electrum_path_root()
        if self.get('testnet'):
            path = os.path.join(path, 'testnet')
            make_dir(path, allow_symlink=False)
        elif self.get('testnet4'):
            path = os.path.join(path, 'testnet4')
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
                os_chmod(path, stat.S_IREAD | stat.S_IWRITE)  # set restrictive perms *before* we write data
                f.write(s)
        except OSError:
            # datadir probably deleted while running... e.g. portable exe running on ejected USB drive
            # (in which case it is typically either FileNotFoundError or PermissionError,
            #  but let's just catch the more generic OSError and test explicitly)
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

        # TODO: this can be removed by now
        # default path in pre 1.9 versions
        old_path = os.path.join(self.path, "electrum.dat")
        if os.path.exists(old_path) and not os.path.exists(new_path):
            os.rename(old_path, new_path)

        return new_path

    def get_datadir_wallet_path(self):
        util.assert_datadir_available(self.path)
        dirpath = os.path.join(self.path, "wallets")
        make_dir(dirpath, allow_symlink=False)
        return dirpath

    def get_fallback_wallet_path(self):
        return os.path.join(self.get_datadir_wallet_path(), "default_wallet")

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
        return f"{depth_mb} {util.UI_UNIT_NAME_MEMPOOL_MB}"

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
            rate_str = format_fee_satoshis(fee_per_byte) + f" {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE}"

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
            return self.FEE_EST_STATIC_FEERATE
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
            fee_rate = self.FEE_EST_STATIC_FEERATE
        if fee_rate is not None:
            fee_rate = int(fee_rate)
        return fee_rate

    def getfeerate(self) -> Tuple[str, int, Optional[int], str]:
        dyn = self.is_dynfee()
        mempool = self.use_mempool_fees()
        if dyn:
            if mempool:
                method = 'mempool'
                fee_level = self.get_depth_level()
                value = self.depth_target(fee_level)
                fee_rate = self.depth_to_fee(fee_level)
                tooltip = self.depth_tooltip(value)
            else:
                method = 'ETA'
                fee_level = self.get_fee_level()
                value = self.eta_target(fee_level)
                fee_rate = self.eta_to_fee(fee_level)
                tooltip = self.eta_tooltip(value)
        else:
            method = 'static'
            value = self.FEE_EST_STATIC_FEERATE
            fee_rate = value
            tooltip = 'static feerate'

        return method, value, fee_rate, tooltip

    def setfeerate(self, fee_method: str, value: int):
        if fee_method == 'mempool':
            if value not in FEE_DEPTH_TARGETS:
                raise Exception(f"Error: fee_level must be in {FEE_DEPTH_TARGETS}")
            self.FEE_EST_USE_MEMPOOL = True
            self.FEE_EST_DYNAMIC = True
            self.FEE_EST_DYNAMIC_MEMPOOL_SLIDERPOS = FEE_DEPTH_TARGETS.index(value)
        elif fee_method == 'ETA':
            if value not in FEE_ETA_TARGETS:
                raise Exception(f"Error: fee_level must be in {FEE_ETA_TARGETS}")
            self.FEE_EST_USE_MEMPOOL = False
            self.FEE_EST_DYNAMIC = True
            self.FEE_EST_DYNAMIC_ETA_SLIDERPOS = FEE_ETA_TARGETS.index(value)
        elif fee_method == 'static':
            self.FEE_EST_DYNAMIC = False
            self.FEE_EST_STATIC_FEERATE = value
        else:
            raise Exception(f"Invalid parameter: {fee_method}. Valid methods are: ETA, mempool, static.")

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
        # note: 'size' is in vbytes
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

    def format_fee_rate(self, fee_rate) -> str:
        """fee_rate is in sat/kvByte."""
        return format_fee_satoshis(fee_rate/1000, num_zeros=self.num_zeros) + f" {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE}"

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
                if name in ("from_key", ):  # don't apply magic, just use standard lookup
                    return super().__getattribute__(name)
                config_var = config.__class__.__getattribute__(type(config), name)
                if not isinstance(config_var, ConfigVar):
                    raise AttributeError()
                return ConfigVarWithConfig(config=config, config_var=config_var)
            def from_key(self, key: str) -> ConfigVarWithConfig:
                try:
                    config_var = _config_var_from_key[key]
                except KeyError:
                    raise KeyError(f"No ConfigVar with key={key!r}") from None
                return ConfigVarWithConfig(config=config, config_var=config_var)
            def __setattr__(self, name, value):
                raise Exception(
                    f"Cannot assign value to config.cv.{name} directly. "
                    f"Either use config.cv.{name}.set() or assign to config.{name} instead.")
        return CVLookupHelper()

    def _default_swapserver_url(self) -> str:
        if constants.net == constants.BitcoinMainnet:
            default = 'https://swaps.electrum.org/api'
        elif constants.net == constants.BitcoinTestnet:
            default = 'https://swaps.electrum.org/testnet'
        else:
            default = 'http://localhost:5455'
        return default

    # config variables ----->
    NETWORK_AUTO_CONNECT = ConfigVar('auto_connect', default=True, type_=bool)
    NETWORK_ONESERVER = ConfigVar('oneserver', default=False, type_=bool)
    NETWORK_PROXY = ConfigVar('proxy', default=None, type_=str, convert_getter=lambda v: "none" if v is None else v)
    NETWORK_PROXY_USER = ConfigVar('proxy_user', default=None, type_=str)
    NETWORK_PROXY_PASSWORD = ConfigVar('proxy_password', default=None, type_=str)
    NETWORK_SERVER = ConfigVar('server', default=None, type_=str)
    NETWORK_NOONION = ConfigVar('noonion', default=False, type_=bool)
    NETWORK_OFFLINE = ConfigVar('offline', default=False, type_=bool)
    NETWORK_SKIPMERKLECHECK = ConfigVar('skipmerklecheck', default=False, type_=bool)
    NETWORK_SERVERFINGERPRINT = ConfigVar('serverfingerprint', default=None, type_=str)
    NETWORK_MAX_INCOMING_MSG_SIZE = ConfigVar('network_max_incoming_msg_size', default=1_000_000, type_=int)  # in bytes
    NETWORK_TIMEOUT = ConfigVar('network_timeout', default=None, type_=int)
    NETWORK_BOOKMARKED_SERVERS = ConfigVar('network_bookmarked_servers', default=None)

    WALLET_BATCH_RBF = ConfigVar(
        'batch_rbf', default=False, type_=bool,
        short_desc=lambda: _('Batch unconfirmed transactions'),
        long_desc=lambda: (
            _('If you check this box, your unconfirmed transactions will be consolidated into a single transaction.') + '\n' +
            _('This will save fees, but might have unwanted effects in terms of privacy')),
    )
    WALLET_MERGE_DUPLICATE_OUTPUTS = ConfigVar(
        'wallet_merge_duplicate_outputs', default=False, type_=bool,
        short_desc=lambda: _('Merge duplicate outputs'),
        long_desc=lambda: _('Merge transaction outputs that pay to the same address into '
                            'a single output that pays the sum of the original amounts.'),
    )
    WALLET_SPEND_CONFIRMED_ONLY = ConfigVar(
        'confirmed_only', default=False, type_=bool,
        short_desc=lambda: _('Spend only confirmed coins'),
        long_desc=lambda: _('Spend only confirmed inputs.'),
    )
    WALLET_COIN_CHOOSER_POLICY = ConfigVar('coin_chooser', default='Privacy', type_=str)
    WALLET_COIN_CHOOSER_OUTPUT_ROUNDING = ConfigVar(
        'coin_chooser_output_rounding', default=True, type_=bool,
        short_desc=lambda: _('Enable output value rounding'),
        long_desc=lambda: (
            _('Set the value of the change output so that it has similar precision to the other outputs.') + '\n' +
            _('This might improve your privacy somewhat.') + '\n' +
            _('If enabled, at most 100 satoshis might be lost due to this, per transaction.')),
    )
    WALLET_UNCONF_UTXO_FREEZE_THRESHOLD_SAT = ConfigVar('unconf_utxo_freeze_threshold', default=5_000, type_=int)
    WALLET_BIP21_LIGHTNING = ConfigVar(
        'bip21_lightning', default=False, type_=bool,
        short_desc=lambda: _('Add lightning requests to bitcoin URIs'),
        long_desc=lambda: _('This may result in large QR codes'),
    )
    WALLET_BOLT11_FALLBACK = ConfigVar(
        'bolt11_fallback', default=True, type_=bool,
        short_desc=lambda: _('Add on-chain fallback to lightning requests'),
    )
    WALLET_PAYREQ_EXPIRY_SECONDS = ConfigVar('request_expiry', default=invoices.PR_DEFAULT_EXPIRATION_WHEN_CREATING, type_=int)
    WALLET_USE_SINGLE_PASSWORD = ConfigVar('single_password', default=False, type_=bool)
    # note: 'use_change' and 'multiple_change' are per-wallet settings
    WALLET_SEND_CHANGE_TO_LIGHTNING = ConfigVar(
        'send_change_to_lightning', default=False, type_=bool,
        short_desc=lambda: _('Send change to Lightning'),
        long_desc=lambda: _('If possible, send the change of this transaction to your channels, with a submarine swap'),
    )

    FX_USE_EXCHANGE_RATE = ConfigVar('use_exchange_rate', default=False, type_=bool)
    FX_CURRENCY = ConfigVar('currency', default='EUR', type_=str)
    FX_EXCHANGE = ConfigVar('use_exchange', default='CoinGecko', type_=str)  # default exchange should ideally provide historical rates
    FX_HISTORY_RATES = ConfigVar(
        'history_rates', default=False, type_=bool,
        short_desc=lambda: _('Download historical rates'),
    )
    FX_HISTORY_RATES_CAPITAL_GAINS = ConfigVar(
        'history_rates_capital_gains', default=False, type_=bool,
        short_desc=lambda: _('Show Capital Gains'),
    )
    FX_SHOW_FIAT_BALANCE_FOR_ADDRESSES = ConfigVar(
        'fiat_address', default=False, type_=bool,
        short_desc=lambda: _('Show Fiat balances'),
    )

    LIGHTNING_LISTEN = ConfigVar('lightning_listen', default=None, type_=str)
    LIGHTNING_PEERS = ConfigVar('lightning_peers', default=None)
    LIGHTNING_USE_GOSSIP = ConfigVar(
        'use_gossip', default=False, type_=bool,
        short_desc=lambda: _("Use trampoline routing"),
        long_desc=lambda: _("""Lightning payments require finding a path through the Lightning Network. You may use trampoline routing, or local routing (gossip).

Downloading the network gossip uses quite some bandwidth and storage, and is not recommended on mobile devices. If you use trampoline, you can only open channels with trampoline nodes."""),
    )
    LIGHTNING_USE_RECOVERABLE_CHANNELS = ConfigVar(
        'use_recoverable_channels', default=True, type_=bool,
        short_desc=lambda: _("Create recoverable channels"),
        long_desc=lambda: _("""Add extra data to your channel funding transactions, so that a static backup can be recovered from your seed.

Note that static backups only allow you to request a force-close with the remote node. This assumes that the remote node is still online, did not lose its data, and accepts to force close the channel.

If this is enabled, other nodes cannot open a channel to you. Channel recovery data is encrypted, so that only your wallet can decrypt it. However, blockchain analysis will be able to tell that the transaction was probably created by Electrum."""),
    )
    LIGHTNING_ALLOW_INSTANT_SWAPS = ConfigVar(
        'allow_instant_swaps', default=False, type_=bool,
        short_desc=lambda: _("Allow instant swaps"),
        long_desc=lambda: _("""If this option is checked, your client will complete reverse swaps before the funding transaction is confirmed.

Note you are at risk of losing the funds in the swap, if the funding transaction never confirms."""),
    )
    LIGHTNING_TO_SELF_DELAY_CSV = ConfigVar('lightning_to_self_delay', default=7 * 144, type_=int)
    LIGHTNING_MAX_FUNDING_SAT = ConfigVar('lightning_max_funding_sat', default=LN_MAX_FUNDING_SAT_LEGACY, type_=int)
    LIGHTNING_LEGACY_ADD_TRAMPOLINE = ConfigVar(
        'lightning_legacy_add_trampoline', default=False, type_=bool,
        short_desc=lambda: _("Add extra trampoline to legacy payments"),
        long_desc=lambda: _("""When paying a non-trampoline invoice, add an extra trampoline to the route, in order to improve your privacy.

This will result in longer routes; it might increase your fees and decrease the success rate of your payments."""),
    )
    INITIAL_TRAMPOLINE_FEE_LEVEL = ConfigVar('initial_trampoline_fee_level', default=1, type_=int)
    LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS = ConfigVar(
        'lightning_payment_fee_max_millionths', default=10_000,  # 1%
        type_=int,
        short_desc=lambda: _("Max lightning fees to pay"),
        long_desc=lambda: _("""When sending lightning payments, this value is an upper bound for the fees we allow paying, proportional to the payment amount. The fees are paid in addition to the payment amount, by the sender.

Warning: setting this to too low will result in lots of payment failures."""),
    )
    LIGHTNING_PAYMENT_FEE_CUTOFF_MSAT = ConfigVar(
        'lightning_payment_fee_cutoff_msat', default=10_000,  # 10 sat
        type_=int,
        short_desc=lambda: _("Max lightning fees to pay for small payments"),
    )

    LIGHTNING_NODE_ALIAS = ConfigVar('lightning_node_alias', default='', type_=str)
    EXPERIMENTAL_LN_FORWARD_PAYMENTS = ConfigVar('lightning_forward_payments', default=False, type_=bool)
    EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = ConfigVar('lightning_forward_trampoline_payments', default=False, type_=bool)
    TEST_FAIL_HTLCS_WITH_TEMP_NODE_FAILURE = ConfigVar('test_fail_htlcs_with_temp_node_failure', default=False, type_=bool)
    TEST_FAIL_HTLCS_AS_MALFORMED = ConfigVar('test_fail_malformed_htlc', default=False, type_=bool)
    TEST_FORCE_MPP = ConfigVar('test_force_mpp', default=False, type_=bool)
    TEST_FORCE_DISABLE_MPP = ConfigVar('test_force_disable_mpp', default=False, type_=bool)
    TEST_SHUTDOWN_FEE = ConfigVar('test_shutdown_fee', default=None, type_=int)
    TEST_SHUTDOWN_FEE_RANGE = ConfigVar('test_shutdown_fee_range', default=None)
    TEST_SHUTDOWN_LEGACY = ConfigVar('test_shutdown_legacy', default=False, type_=bool)

    FEE_EST_DYNAMIC = ConfigVar('dynamic_fees', default=True, type_=bool)
    FEE_EST_USE_MEMPOOL = ConfigVar('mempool_fees', default=False, type_=bool)
    FEE_EST_STATIC_FEERATE = ConfigVar('fee_per_kb', default=FEERATE_FALLBACK_STATIC_FEE, type_=int)
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

    GUI_QT_COLOR_THEME = ConfigVar(
        'qt_gui_color_theme', default='default', type_=str,
        short_desc=lambda: _('Color theme'),
    )
    GUI_QT_DARK_TRAY_ICON = ConfigVar('dark_icon', default=False, type_=bool)
    GUI_QT_WINDOW_IS_MAXIMIZED = ConfigVar('is_maximized', default=False, type_=bool)
    GUI_QT_HIDE_ON_STARTUP = ConfigVar('hide_gui', default=False, type_=bool)
    GUI_QT_HISTORY_TAB_SHOW_TOOLBAR = ConfigVar('show_toolbar_history', default=False, type_=bool)
    GUI_QT_ADDRESSES_TAB_SHOW_TOOLBAR = ConfigVar('show_toolbar_addresses', default=False, type_=bool)
    GUI_QT_TX_DIALOG_FETCH_TXIN_DATA = ConfigVar(
        'tx_dialog_fetch_txin_data', default=False, type_=bool,
        short_desc=lambda: _('Download missing data'),
        long_desc=lambda: _(
            'Download parent transactions from the network.\n'
            'Allows filling in missing fee and input details.'),
    )
    GUI_QT_TX_DIALOG_EXPORT_STRIP_SENSITIVE_METADATA = ConfigVar(
        'gui_qt_tx_dialog_export_strip_sensitive_metadata', default=False, type_=bool,
        short_desc=lambda: _('For CoinJoin; strip privates'),
    )
    GUI_QT_TX_DIALOG_EXPORT_INCLUDE_GLOBAL_XPUBS = ConfigVar(
        'gui_qt_tx_dialog_export_include_global_xpubs', default=False, type_=bool,
        short_desc=lambda: _('For hardware device; include xpubs'),
    )
    GUI_QT_RECEIVE_TABS_INDEX = ConfigVar('receive_tabs_index', default=0, type_=int)
    GUI_QT_RECEIVE_TAB_QR_VISIBLE = ConfigVar('receive_qr_visible', default=False, type_=bool)
    GUI_QT_TX_EDITOR_SHOW_IO = ConfigVar(
        'show_tx_io', default=False, type_=bool,
        short_desc=lambda: _('Show inputs and outputs'),
    )
    GUI_QT_TX_EDITOR_SHOW_FEE_DETAILS = ConfigVar(
        'show_tx_fee_details', default=False, type_=bool,
        short_desc=lambda: _('Edit fees manually'),
    )
    GUI_QT_TX_EDITOR_SHOW_LOCKTIME = ConfigVar(
        'show_tx_locktime', default=False, type_=bool,
        short_desc=lambda: _('Edit Locktime'),
    )
    GUI_QT_SHOW_TAB_ADDRESSES = ConfigVar('show_addresses_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_CHANNELS = ConfigVar('show_channels_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_UTXO = ConfigVar('show_utxo_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_CONTACTS = ConfigVar('show_contacts_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_CONSOLE = ConfigVar('show_console_tab', default=False, type_=bool)
    GUI_QT_SHOW_TAB_NOTES = ConfigVar('show_notes_tab', default=False, type_=bool)

    GUI_QML_PREFERRED_REQUEST_TYPE = ConfigVar('preferred_request_type', default='bolt11', type_=str)
    GUI_QML_USER_KNOWS_PRESS_AND_HOLD = ConfigVar('user_knows_press_and_hold', default=False, type_=bool)
    GUI_QML_ADDRESS_LIST_SHOW_TYPE = ConfigVar('address_list_show_type', default=1, type_=int)
    GUI_QML_ADDRESS_LIST_SHOW_USED = ConfigVar('address_list_show_used', default=False, type_=bool)
    GUI_QML_ALWAYS_ALLOW_SCREENSHOTS = ConfigVar('android_always_allow_screenshots', default=False, type_=bool)

    BTC_AMOUNTS_DECIMAL_POINT = ConfigVar('decimal_point', default=DECIMAL_POINT_DEFAULT, type_=int)
    BTC_AMOUNTS_FORCE_NZEROS_AFTER_DECIMAL_POINT = ConfigVar(
        'num_zeros', default=0, type_=int,
        short_desc=lambda: _('Zeros after decimal point'),
        long_desc=lambda: _('Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"'),
    )
    BTC_AMOUNTS_PREC_POST_SAT = ConfigVar(
        'amt_precision_post_satoshi', default=0, type_=int,
        short_desc=lambda: _("Show Lightning amounts with msat precision"),
    )
    BTC_AMOUNTS_ADD_THOUSANDS_SEP = ConfigVar(
        'amt_add_thousands_sep', default=False, type_=bool,
        short_desc=lambda: _("Add thousand separators to bitcoin amounts"),
    )

    BLOCK_EXPLORER = ConfigVar(
        'block_explorer', default='Blockstream.info', type_=str,
        short_desc=lambda: _('Online Block Explorer'),
        long_desc=lambda: _('Choose which online block explorer to use for functions that open a web browser'),
    )
    BLOCK_EXPLORER_CUSTOM = ConfigVar('block_explorer_custom', default=None)
    VIDEO_DEVICE_PATH = ConfigVar(
        'video_device', default='default', type_=str,
        short_desc=lambda: _('Video Device'),
        long_desc=lambda: (_("For scanning QR codes.") + "\n" +
                           _("Install the zbar package to enable this.")),
    )
    OPENALIAS_ID = ConfigVar(
        'alias', default="", type_=str,
        short_desc=lambda: 'OpenAlias',
        long_desc=lambda: (
            _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n' +
            _('The following alias providers are available:') + '\n' +
            '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n' +
            'For more information, see https://openalias.org'),
    )
    HWD_SESSION_TIMEOUT = ConfigVar('session_timeout', default=300, type_=int)
    CLI_TIMEOUT = ConfigVar('timeout', default=60, type_=float)
    AUTOMATIC_CENTRALIZED_UPDATE_CHECKS = ConfigVar(
        'check_updates', default=False, type_=bool,
        short_desc=lambda: _("Automatically check for software updates"),
    )
    WRITE_LOGS_TO_DISK = ConfigVar(
        'log_to_file', default=False, type_=bool,
        short_desc=lambda: _("Write logs to file"),
        long_desc=lambda: _('Debug logs can be persisted to disk. These are useful for troubleshooting.'),
    )
    LOGS_NUM_FILES_KEEP = ConfigVar('logs_num_files_keep', default=10, type_=int)
    GUI_ENABLE_DEBUG_LOGS = ConfigVar('gui_enable_debug_logs', default=False, type_=bool)
    LOCALIZATION_LANGUAGE = ConfigVar(
        'language', default="", type_=str,
        short_desc=lambda: _("Language"),
        long_desc=lambda: _("Select which language is used in the GUI (after restart)."),
    )
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

    # connect to remote submarine swap server
    SWAPSERVER_URL = ConfigVar('swapserver_url', default=_default_swapserver_url, type_=str)
    # run submarine swap server locally
    SWAPSERVER_PORT = ConfigVar('swapserver_port', default=5455, type_=int)
    TEST_SWAPSERVER_REFUND = ConfigVar('test_swapserver_refund', default=False, type_=bool)

    # zeroconf channels
    ACCEPT_ZEROCONF_CHANNELS = ConfigVar('accept_zeroconf_channels', default=False, type_=bool)
    ZEROCONF_TRUSTED_NODE = ConfigVar('zeroconf_trusted_node', default='', type_=str)
    ZEROCONF_MIN_OPENING_FEE = ConfigVar('zeroconf_min_opening_fee', default=5000, type_=int)

    # connect to remote WT
    WATCHTOWER_CLIENT_ENABLED = ConfigVar(
        'use_watchtower', default=False, type_=bool,
        short_desc=lambda: _("Use a remote watchtower"),
        long_desc=lambda: ' '.join([
            _("A watchtower is a daemon that watches your channels and prevents the other party from stealing funds by broadcasting an old state."),
            _("If you have private a watchtower, enter its URL here."),
            _("Check our online documentation if you want to configure Electrum as a watchtower."),
        ]),
    )
    WATCHTOWER_CLIENT_URL = ConfigVar('watchtower_url', default=None, type_=str)

    # run WT locally
    WATCHTOWER_SERVER_ENABLED = ConfigVar('run_watchtower', default=False, type_=bool)
    WATCHTOWER_SERVER_PORT = ConfigVar('watchtower_port', default=None, type_=int)
    WATCHTOWER_SERVER_USER = ConfigVar('watchtower_user', default=None, type_=str)
    WATCHTOWER_SERVER_PASSWORD = ConfigVar('watchtower_password', default=None, type_=str)

    PAYSERVER_PORT = ConfigVar('payserver_port', default=8080, type_=int)
    PAYSERVER_ROOT = ConfigVar('payserver_root', default='/r', type_=str)
    PAYSERVER_ALLOW_CREATE_INVOICE = ConfigVar('payserver_allow_create_invoice', default=False, type_=bool)

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
