import json
import threading
import time
import os
import stat

from . import util
from copy import deepcopy
from .util import user_dir, make_dir, print_error, PrintError

from .bitcoin import MAX_FEE_RATE, FEE_TARGETS

config = None


def get_config():
    global config
    return config


def set_config(c):
    global config
    config = c


FINAL_CONFIG_VERSION = 2


class SimpleConfig(PrintError):
    """
    The SimpleConfig class is responsible for handling operations involving
    configuration files.

    There are two different sources of possible configuration values:
        1. Command line options.
        2. User configuration (in the user's config directory)
    They are taken in order (1. overrides config options set in 2.)
    """
    fee_rates = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000]

    def __init__(self, options=None, read_user_config_function=None,
                 read_user_dir_function=None):

        if options is None:
            options = {}

        # This lock needs to be acquired for updating and reading the config in
        # a thread-safe way.
        self.lock = threading.RLock()

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
        # Read electrum_cash_path from command line
        # Otherwise use the user's default data directory.
        path = self.get('electron_cash_path')
        if path is None:
            path = self.user_dir()

        make_dir(path)
        if self.get('testnet4'):
            path = os.path.join(path, 'testnet4')
            make_dir(path)
        elif self.get('testnet'):
            path = os.path.join(path, 'testnet')
            make_dir(path)

        obsolete_file = os.path.join(path, 'recent_servers')
        if os.path.exists(obsolete_file):
            os.remove(obsolete_file)
        self.print_error("electron-cash directory", path)
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
            server_str = str('{}:{}:s'.format(host, port))
            self._set_key_in_user_config('server', server_str)
        except BaseException:
            self._set_key_in_user_config('server', None)

        self.set_key('config_version', 2)

    def _is_upgrade_method_needed(self, min_version, max_version):
        cur_version = self.get_config_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise BaseException(
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
        with open(path, "w", encoding='utf-8') as f:
            f.write(s)
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)

    def get_wallet_path(self):
        """Set the path of the wallet."""

        # command line -w option
        if self.get('wallet_path'):
            return os.path.join(self.get('cwd', ''), self.get('wallet_path'))

        # path in config file
        path = self.get('default_wallet_path')
        if path and os.path.exists(path):
            return path

        # default path
        util.assert_datadir_available(self.path)
        dirpath = os.path.join(self.path, "wallets")
        make_dir(dirpath)

        new_path = os.path.join(self.path, "wallets", "default_wallet")

        # default path in pre 1.9 versions
        old_path = os.path.join(self.path, "electrum.dat")
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

    def max_fee_rate(self):
        return self.fee_rates[-1]
        #
        #f = self.get('max_fee_rate', MAX_FEE_RATE)
        #if f==0:
        #    f = MAX_FEE_RATE
        #return f

    def dynfee(self, i):
        if i < 4:
            j = FEE_TARGETS[i]
            fee = self.fee_estimates.get(j)
        else:
            assert i == 4
            fee = self.fee_estimates.get(2)
            if fee is not None:
                fee += fee/2
        if fee is not None:
            fee = min(5*MAX_FEE_RATE, fee)
        return fee

    def reverse_dynfee(self, fee_per_kb):
        import operator
        l = list(self.fee_estimates.items()) + [(1, self.dynfee(4))]
        dist = map(lambda x: (x[0], abs(x[1] - fee_per_kb)), l)
        min_target, min_value = min(dist, key=operator.itemgetter(1))
        if fee_per_kb < self.fee_estimates.get(25)/2:
            min_target = -1
        return min_target

    def static_fee(self, i):
        return self.fee_rates[i]

    def static_fee_index(self, value):
        dist = list(map(lambda x: abs(x - value), self.fee_rates))
        return min(range(len(dist)), key=dist.__getitem__)

    def has_fee_estimates(self):
        #return len(self.fee_estimates)==4
        # We disabled fee estimates for BCH.  They do more harm than good.
        # Our blocks aren't full and it is not the intention for them to ever
        # be full according to all the full node implementers.  This is a
        # coreism that must die. :)
        return False

    def custom_fee_rate(self):
        f = self.get('customfee')
        return f

    def fee_per_kb(self):
       retval = self.get('customfee')
       if retval is None:
           retval = self.get('fee_per_kb')
       if retval is None:
           retval = 1000  # New wallet
       return retval

    def has_custom_fee_rate(self):
        i = -1
        # Defensive programming below.. to ensure the custom fee rate is valid ;)
        # This function mainly controls the appearance (or disappearance) of the fee slider in the send tab in Qt GUI
        # It is tied to the GUI preferences option 'Custom fee rate'.
        try:
            i = int(self.custom_fee_rate())
        except (ValueError, TypeError):
            pass
        return i >= 0

    def estimate_fee(self, size):
        return int(self.fee_per_kb() * size / 1000.)

    def update_fee_estimates(self, key, value):
        self.fee_estimates[key] = value
        self.fee_estimates_last_updated[key] = time.time()

    def is_fee_estimates_update_required(self):
        """Checks time since last requested and updated fee estimates.
        Returns True if an update should be requested.
        """
        return False # For now we disable fee estimates altogether. This is BCH. 1.0 sats/B pretty much works.
        # /
        now = time.time()
        prev_updates = self.fee_estimates_last_updated.values()
        oldest_fee_time = min(prev_updates) if prev_updates else 0
        stale_fees = now - oldest_fee_time > 1200 # 20 mins.
        old_request = now - self.last_time_fee_estimates_requested > 60
        return stale_fees and old_request

    def requested_fee_estimates(self):
        self.last_time_fee_estimates_requested = time.time()

    def get_video_device(self):
        device = self.get("video_device", "default")
        if device == 'default':
            device = ''
        return device


def read_user_config(path):
    """Parse and store the user config settings in electron-cash.conf into user_config[]."""
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
