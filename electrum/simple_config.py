import json
import threading
import os
import stat
from typing import Union, Optional, Dict, Sequence, Any, Set, Callable, AbstractSet, Type
from functools import cached_property

from copy import deepcopy

from . import constants
from . import util
from . import invoices
from .util import base_units, base_unit_name_to_decimal_point, decimal_point_to_base_unit_name, UnknownBaseUnit, DECIMAL_POINT_DEFAULT
from .util import format_satoshis, format_fee_satoshis, os_chmod
from .util import user_dir, make_dir
from .util import is_valid_websocket_url
from .lnutil import LN_MAX_FUNDING_SAT_LEGACY
from .i18n import _
from .logging import get_logger, Logger


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
        convert_setter: Callable[[Any], Any] = None,
        short_desc: Callable[[], str] = None,
        long_desc: Callable[[], str] = None,
        plugin: Optional[str] = None,
    ):
        self._key = key
        self._default = default
        self._type = type_
        self._convert_getter = convert_getter
        self._convert_setter = convert_setter
        # note: the descriptions are callables instead of str literals, to delay evaluating the _() translations
        #       until after the language is set.
        assert short_desc is None or callable(short_desc)
        assert long_desc is None or callable(long_desc)
        self._short_desc = short_desc
        self._long_desc = long_desc
        if plugin:  # enforce "key" starts with 'plugins.<name of plugin>.'
            pkg_prefix = "electrum.plugins."  # for internal plugins
            if plugin.startswith(pkg_prefix):
                plugin = plugin[len(pkg_prefix):]
            assert "." not in plugin, plugin
            key_prefix = f'plugins.{plugin}.'
            assert key.startswith(key_prefix), f"ConfigVar {key=} must be prefixed with ({key_prefix})"
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
        # run converter
        if self._convert_setter is not None and value is not None:
            value = self._convert_setter(value)
        # type-check
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
        for config_key in options:
            assert isinstance(config_key, str), f"{config_key=!r} has type={type(config_key)}, expected str"

        Logger.__init__(self)

        # This lock needs to be acquired for updating and reading the config in
        # a thread-safe way.
        self.lock = threading.RLock()

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

        self._init_done = True

    def list_config_vars(self) -> Sequence[str]:
        return list(sorted(_config_var_from_key.keys()))

    def electrum_path_root(self):
        # Read electrum_path from command line
        # Otherwise use the user's default data directory.
        path = self.get('electrum_path') or self.user_dir()
        make_dir(path, allow_symlink=False)
        return path

    @classmethod
    def set_chain_config_opt_based_on_android_packagename(cls, config_options: dict[str, Any]) -> None:
        # ~hack for easier testnet builds. pkgname subject to change.
        android_pkg_name = util.get_android_package_name()
        for chain in constants.NETS_LIST:
            if android_pkg_name == f"org.electrum.{chain.cli_flag()}.electrum":
                config_options[chain.cli_flag()] = True

    def get_selected_chain(self) -> Type[constants.AbstractNet]:
        selected_chains = [
            chain for chain in constants.NETS_LIST
            if self.get(chain.config_key())]
        if selected_chains:
            # note: if multiple are selected, we just pick one deterministically random
            return selected_chains[0]
        return constants.BitcoinMainnet

    def electrum_path(self):
        path = self.electrum_path_root()
        chain = self.get_selected_chain()
        if subdir := chain.datadir_subdir():
            path = os.path.join(path, subdir)
            make_dir(path, allow_symlink=False)

        self.logger.info(f"electrum directory {path} (chain={chain.NET_NAME})")
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
                keypath = key.split('.')
                d = self.user_config
                for x in keypath[0:-1]:
                    d2 = d.get(x)
                    if not isinstance(d2, dict):
                        d2 = d[x] = {}
                    d = d2
                d[keypath[-1]] = value
            else:
                def delete_key(d, key):
                    if '.' not in key:
                        d.pop(key, None)
                    else:
                        prefix, suffix = key.split('.', 1)
                        d2 = d.get(prefix)
                        empty = delete_key(d2, suffix)
                        if empty:
                            d.pop(prefix)
                    return len(d) == 0
                delete_key(self.user_config, key)
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
                d = self.user_config
                path = key.split('.')
                for key in path[0:-1]:
                    d = d.get(key, {})
                if not isinstance(d, dict):
                    d = {}
                out = d.get(path[-1], default)
        return out

    def is_set(self, key: Union[str, ConfigVar, ConfigVarWithConfig]) -> bool:
        """Returns whether the config key has any explicit value set/defined."""
        if isinstance(key, (ConfigVar, ConfigVarWithConfig)):
            key = key.key()
        assert isinstance(key, str), key
        return self.get(key, default=...) is not ...

    def is_plugin_enabled(self, name: str) -> bool:
        return bool(self.get(f'plugins.{name}.enabled'))

    def get_installed_plugins(self) -> AbstractSet[str]:
        """Returns all plugin names registered in the config."""
        return self.get('plugins', {}).keys()

    def enable_plugin(self, name: str):
        self.set_key(f'plugins.{name}.enabled', True, save=True)

    def disable_plugin(self, name: str):
        self.set_key(f'plugins.{name}.enabled', False, save=True)

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
            map_ = {'btc': 8, 'mbtc': 5, 'ubtc': 2, 'bits': 2, 'sat': 0}
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

    def maybe_complete_wallet_path(self, path: Optional[str]) -> str:
        return self._complete_wallet_path(path) if path is not None else self.get_wallet_path()

    def _complete_wallet_path(self, path: str) -> str:
        """ add user wallets directory if needed """
        if os.path.split(path)[0] == '':
            path = os.path.join(self.get_datadir_wallet_path(), path)
        return path

    def get_wallet_path(self) -> str:
        """Returns the wallet path."""
        # command line -w option
        if path:= self.get('wallet_path'):
            return self._complete_wallet_path(path)
        # current wallet
        path = self.CURRENT_WALLET
        if path and os.path.exists(path):
            return path
        return self.get_fallback_wallet_path()

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

    def get_nostr_relays(self) -> Sequence[str]:
        relays = []
        for url in self.NOSTR_RELAYS.split(','):
            url = url.strip()
            if url and is_valid_websocket_url(url):
                relays.append(url)
        return relays

    def add_nostr_relay(self, relay: str):
        l = self.get_nostr_relays()
        if is_valid_websocket_url(relay) and relay not in l:
            l.append(relay)
            self.NOSTR_RELAYS = ','.join(l)

    def remove_nostr_relay(self, relay: str):
        l = self.get_nostr_relays()
        if relay in l:
            l.remove(relay)
            self.NOSTR_RELAYS = ','.join(l)

    def __setattr__(self, name, value):
        """Disallows setting instance attributes outside __init__.

        The point is to make the following code raise:
        >>> config.NETORK_AUTO_CONNECTT = False
        (i.e. catch mistyped or non-existent ConfigVars)
        """
        # If __init__ not finished yet, or this field already exists, set it:
        if not getattr(self, "_init_done", False) or hasattr(self, name):
            return super().__setattr__(name, value)
        raise AttributeError(
            f"Tried to define new instance attribute for config: {name=!r}. "
            "Did you perhaps mistype a ConfigVar?"
        )

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

    # config variables ----->
    NETWORK_AUTO_CONNECT = ConfigVar(
        'auto_connect', default=True, type_=bool,
        short_desc=lambda: _('Select server automatically'),
        long_desc=lambda: _("If auto-connect is enabled, Electrum will always use a server that is on the longest blockchain. "
                            "If it is disabled, you have to choose a server you want to use. Electrum will warn you if your server is lagging."),
    )
    NETWORK_ONESERVER = ConfigVar(
        'oneserver', default=False, type_=bool,
        short_desc=lambda: _('Only connect to one server (full trust)'),
        long_desc=lambda: _(
            "This is only intended for connecting to your own fully trusted server. "
            "Using this option on a public server is a security risk and is discouraged."
            "\n\n"
            "By default, Electrum tries to maintain connections to ~10 servers. "
            "One of these nodes gets selected to be the history server and will learn the wallet addresses. "
            "All the other nodes are *only* used for block header notifications. "
            "\n\n"
            "Getting block headers from multiple sources is useful to detect lagging servers, chain splits, and forks. "
            "Chain split detection is security-critical for determining number of confirmations."
        )
    )
    NETWORK_PROXY = ConfigVar('proxy', default=None, type_=str, convert_getter=lambda v: "none" if v is None else v)
    NETWORK_PROXY_USER = ConfigVar('proxy_user', default=None, type_=str)
    NETWORK_PROXY_PASSWORD = ConfigVar('proxy_password', default=None, type_=str)
    NETWORK_PROXY_ENABLED = ConfigVar('enable_proxy', default=lambda config: config.NETWORK_PROXY not in [None, "none"], type_=bool)
    NETWORK_SERVER = ConfigVar('server', default=None, type_=str)
    NETWORK_NOONION = ConfigVar('noonion', default=False, type_=bool)
    NETWORK_OFFLINE = ConfigVar('offline', default=False, type_=bool)
    NETWORK_SKIPMERKLECHECK = ConfigVar('skipmerklecheck', default=False, type_=bool)
    NETWORK_SERVERFINGERPRINT = ConfigVar('serverfingerprint', default=None, type_=str)
    NETWORK_MAX_INCOMING_MSG_SIZE = ConfigVar('network_max_incoming_msg_size', default=8_100_000, type_=int)  # in bytes
        # ^ the default is chosen so that the largest consensus-valid tx fits in a JSON-RPC message.
        #   (so that if we request a tx from the server, we won't reject the response)
        #   For Bitcoin, that is 4 M weight units, i.e. 4 MB on the p2p wire.
        #   Double that due to our JSON-RPC hex-encoding, plus overhead, that's 8+ MB.
    NETWORK_TIMEOUT = ConfigVar('network_timeout', default=None, type_=int)
    NETWORK_BOOKMARKED_SERVERS = ConfigVar('network_bookmarked_servers', default=None)

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
    WALLET_PAYREQ_EXPIRY_SECONDS = ConfigVar('request_expiry', default=invoices.PR_DEFAULT_EXPIRATION_WHEN_CREATING, type_=int)
    WALLET_USE_SINGLE_PASSWORD = ConfigVar('single_password', default=False, type_=bool)
    # note: 'use_change' and 'multiple_change' are per-wallet settings
    WALLET_SEND_CHANGE_TO_LIGHTNING = ConfigVar(
        'send_change_to_lightning', default=False, type_=bool,
        short_desc=lambda: _('Send change to Lightning'),
        long_desc=lambda: _('If possible, send the change of this transaction to your channels, with a submarine swap'),
    )
    WALLET_FREEZE_REUSED_ADDRESS_UTXOS = ConfigVar(
        'wallet_freeze_reused_address_utxos', default=False, type_=bool,
        short_desc=lambda: _('Avoid spending from used addresses'),
        long_desc=lambda: _("""Automatically freeze coins received to already used addresses.
This can eliminate a serious privacy issue where a malicious user can track your spends by sending small payments
to a previously-paid address of yours that would then be included with unrelated inputs in your future payments."""),
    )
    WALLET_PARTIAL_WRITES = ConfigVar(
        'wallet_partial_writes', default=True, type_=bool,
        long_desc=lambda: _("""Allows partial updates to be written to disk for the wallet DB.
If disabled, the full wallet file is written to disk for every change. Experimental."""),
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

    LIGHTNING_LISTEN = ConfigVar(
        'lightning_listen', default=None, type_=str,
        long_desc=lambda: _("""By default the client does not listen on any port for incoming BOLT-08 transports.
Set this to an interface:port combination, such as 'localhost:9735', to open a port and start listening.

Note: if you open multiple lightning wallets, they will all try to bind the same port, conflict, and only the first will succeed."""),
    )
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
    LIGHTNING_TO_SELF_DELAY_CSV = ConfigVar('lightning_to_self_delay', default=7 * 144, type_=int)
    LIGHTNING_MAX_FUNDING_SAT = ConfigVar('lightning_max_funding_sat', default=LN_MAX_FUNDING_SAT_LEGACY, type_=int)
    LIGHTNING_MAX_HTLC_VALUE_IN_FLIGHT_MSAT = ConfigVar('lightning_max_htlc_value_in_flight_msat', default=None, type_=int)
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
    LIGHTNING_NODE_COLOR_RGB = ConfigVar('lightning_node_color_rgb', default='000000', type_=str)
    EXPERIMENTAL_LN_FORWARD_PAYMENTS = ConfigVar('lightning_forward_payments', default=False, type_=bool)
    EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = ConfigVar('lightning_forward_trampoline_payments', default=False, type_=bool)
    TEST_FAIL_HTLCS_WITH_TEMP_NODE_FAILURE = ConfigVar('test_fail_htlcs_with_temp_node_failure', default=False, type_=bool)
    TEST_FAIL_HTLCS_AS_MALFORMED = ConfigVar('test_fail_malformed_htlc', default=False, type_=bool)
    TEST_FORCE_MPP = ConfigVar('test_force_mpp', default=False, type_=bool)
    TEST_FORCE_DISABLE_MPP = ConfigVar('test_force_disable_mpp', default=False, type_=bool)
    TEST_SHUTDOWN_FEE = ConfigVar('test_shutdown_fee', default=None, type_=int)
    TEST_SHUTDOWN_FEE_RANGE = ConfigVar('test_shutdown_fee_range', default=None)
    TEST_SHUTDOWN_LEGACY = ConfigVar('test_shutdown_legacy', default=False, type_=bool)

    # fee_policy is a dict: fee_policy_name -> fee_policy_descriptor
    FEE_POLICY = ConfigVar('fee_policy.default', default='eta:2', type_=str)  # exposed to GUI
    FEE_POLICY_LIGHTNING = ConfigVar('fee_policy.lnwatcher', default='eta:2', type_=str)  # for txbatcher (sweeping)
    FEE_POLICY_SWAPS = ConfigVar('fee_policy.swaps', default='eta:2', type_=str)  # for txbatcher (sweeping and sending if we are a swapserver)

    RPC_USERNAME = ConfigVar('rpcuser', default=None, type_=str)
    RPC_PASSWORD = ConfigVar('rpcpassword', default=None, type_=str)
    RPC_HOST = ConfigVar('rpchost', default='127.0.0.1', type_=str)
    RPC_PORT = ConfigVar('rpcport', default=0, type_=int)
    RPC_SOCKET_TYPE = ConfigVar('rpcsock', default='auto', type_=str)
    RPC_SOCKET_FILEPATH = ConfigVar('rpcsockpath', default=None, type_=str)

    GUI_NAME = ConfigVar('gui', default='qt', type_=str)
    CURRENT_WALLET = ConfigVar('current_wallet', default=None, type_=str)

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
    GUI_QT_SCREENSHOT_PROTECTION = ConfigVar(
        'screenshot_protection', default=True, type_=bool,
        short_desc=lambda: _("Prevent screenshots"),
        # currently this option is Windows only, so the description can be specific to Windows
        long_desc=lambda: _(
            'Signals Windows to disallow recordings and screenshots of the application window. '
            'There is no guarantee Windows will respect this signal.'),
    )

    GUI_QML_PREFERRED_REQUEST_TYPE = ConfigVar('preferred_request_type', default='bolt11', type_=str)
    GUI_QML_USER_KNOWS_PRESS_AND_HOLD = ConfigVar('user_knows_press_and_hold', default=False, type_=bool)
    GUI_QML_ADDRESS_LIST_SHOW_TYPE = ConfigVar('address_list_show_type', default=1, type_=int)
    GUI_QML_ADDRESS_LIST_SHOW_USED = ConfigVar('address_list_show_used', default=False, type_=bool)
    GUI_QML_ALWAYS_ALLOW_SCREENSHOTS = ConfigVar('android_always_allow_screenshots', default=False, type_=bool)
    GUI_QML_SET_MAX_BRIGHTNESS_ON_QR_DISPLAY = ConfigVar('android_set_max_brightness_on_qr_display', default=True, type_=bool)

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
    CLI_TIMEOUT = ConfigVar('timeout', default=60.0, type_=float, convert_setter=lambda v: float(v))
    AUTOMATIC_CENTRALIZED_UPDATE_CHECKS = ConfigVar(
        'check_updates', default=False, type_=bool,
        short_desc=lambda: _("Automatically check for software updates"),
    )
    WRITE_LOGS_TO_DISK = ConfigVar(
        'log_to_file', default=False, type_=bool,
        short_desc=lambda: _("Write logs to file"),
        long_desc=lambda: _('Debug logs can be persisted to disk. These are useful for troubleshooting.'),
    )
    LOGS_NUM_FILES_KEEP = ConfigVar(
        'logs_num_files_keep', default=30, type_=int,
        long_desc=lambda: _("Old log files get deleted on startup, with only the newest few being kept."),
    )
    LOGS_MAX_TOTAL_SIZE_BYTES = ConfigVar(
        'logs_max_total_size', default=200_000_000, type_=int,
        long_desc=lambda: _(
            "Old log files get deleted on startup. "
            "This value limits the max total size of the old log files kept, "
            "and also separately the max size of the current log file. "
            "Hence, the max disk usage will be twice this value."),
    )
    GUI_ENABLE_DEBUG_LOGS = ConfigVar('gui_enable_debug_logs', default=False, type_=bool)
    LOCALIZATION_LANGUAGE = ConfigVar(
        'language', default="", type_=str,
        short_desc=lambda: _("Language"),
        long_desc=lambda: _("Select which language is used in the GUI (after restart)."),
    )
    BLOCKCHAIN_PREFERRED_BLOCK = ConfigVar('blockchain_preferred_block', default=None)
    DONT_SHOW_TESTNET_WARNING = ConfigVar('dont_show_testnet_warning', default=False, type_=bool)
    RECENTLY_OPEN_WALLET_FILES = ConfigVar('recently_open', default=None)
    IO_DIRECTORY = ConfigVar('io_dir', default=os.path.expanduser('~'), type_=str)
    WALLET_BACKUP_DIRECTORY = ConfigVar('backup_dir', default=None, type_=str)
    CONFIG_PIN_CODE = ConfigVar('pin_code', default=None, type_=str)
    QR_READER_FLIP_X = ConfigVar('qrreader_flip_x', default=True, type_=bool)
    WIZARD_DONT_CREATE_SEGWIT = ConfigVar('nosegwit', default=False, type_=bool)
    CONFIG_FORGET_CHANGES = ConfigVar('forget_config', default=False, type_=bool)
    TERMS_OF_USE_ACCEPTED = ConfigVar('terms_of_use_accepted', default=0, type_=int)

    # connect to remote submarine swap server
    SWAPSERVER_URL = ConfigVar('swapserver_url', default='', type_=str)
    TEST_SWAPSERVER_REFUND = ConfigVar('test_swapserver_refund', default=False, type_=bool)
    SWAPSERVER_NPUB = ConfigVar('swapserver_npub', default=None, type_=str)
    SWAPSERVER_POW_TARGET = ConfigVar('swapserver_pow_target', default=30, type_=int)

    # nostr
    NOSTR_RELAYS = ConfigVar(
        'nostr_relays',
        default='wss://relay.getalby.com/v1,wss://nos.lol,wss://relay.damus.io,wss://brb.io,'
                'wss://relay.primal.net,wss://ftp.halifax.rwth-aachen.de/nostr,'
                'wss://eu.purplerelay.com,wss://nostr.einundzwanzig.space,wss://nostr.mom',
        type_=str,
        short_desc=lambda: _("Nostr relays"),
        long_desc=lambda: ' '.join([
            _('Nostr relays are used to send and receive submarine swap offers.'),
            _('These relays are also used for some plugins, e.g. Nostr Wallet Connect or Nostr Cosigner'),
        ]),
    )

    # anchor outputs channels
    ENABLE_ANCHOR_CHANNELS = ConfigVar('enable_anchor_channels', default=True, type_=bool)
    # zeroconf channels
    ACCEPT_ZEROCONF_CHANNELS = ConfigVar('accept_zeroconf_channels', default=False, type_=bool)
    ZEROCONF_TRUSTED_NODE = ConfigVar('zeroconf_trusted_node', default='', type_=str)
    ZEROCONF_MIN_OPENING_FEE = ConfigVar('zeroconf_min_opening_fee', default=5000, type_=int)
    LN_UTXO_RESERVE = ConfigVar(
        'ln_utxo_reserve',
        default=10000,
        type_=int,
        short_desc=lambda: _("Amount that must be kept on-chain in order to sweep anchor output channels"),
        long_desc=lambda: _("Do not set this below dust limit"),
    )

    # connect to remote WT
    WATCHTOWER_CLIENT_URL = ConfigVar('watchtower_url', default=None, type_=str)

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
        assert isinstance(result, dict), "config file is not a dict"
    except Exception as e:
        raise ValueError(f"Invalid config file at {config_path}: {str(e)}")
    return result
