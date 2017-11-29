import json
import threading
import time
import os
import stat

from copy import deepcopy
from .util import user_dir, print_error, print_stderr, PrintError

from .bitcoin import MAX_FEE_RATE, FEE_TARGETS

SYSTEM_CONFIG_PATH = "/etc/electrum.conf"

config = None


def get_config():
    global config
    return config


def set_config(c):
    global config
    config = c


class SimpleConfig(PrintError):
    """
    The SimpleConfig class is responsible for handling operations involving
    configuration files.

    There are 3 different sources of possible configuration values:
        1. Command line options.
        2. User configuration (in the user's config directory)
        3. System configuration (in /etc/)
    They are taken in order (1. overrides config options set in 2., that
    override config set in 3.)
    """
    fee_rates = [5000, 10000, 20000, 30000, 50000, 70000, 100000, 150000, 200000, 300000]

    def __init__(self, options={}, read_system_config_function=None,
                 read_user_config_function=None, read_user_dir_function=None):

        # This lock needs to be acquired for updating and reading the config in
        # a thread-safe way.
        self.lock = threading.RLock()

        self.fee_estimates = {}
        self.fee_estimates_last_updated = {}
        self.last_time_fee_estimates_requested = 0  # zero ensures immediate fees

        # The following two functions are there for dependency injection when
        # testing.
        if read_system_config_function is None:
            read_system_config_function = read_system_config
        if read_user_config_function is None:
            read_user_config_function = read_user_config
        if read_user_dir_function is None:
            self.user_dir = user_dir
        else:
            self.user_dir = read_user_dir_function

        # The command line options
        self.cmdline_options = deepcopy(options)

        # Portable wallets don't use a system config
        if self.cmdline_options.get('portable', False):
            self.system_config = {}
        else:
            self.system_config = read_system_config_function()

        # Set self.path and read the user config
        self.user_config = {}  # for self.get in electrum_path()
        self.path = self.electrum_path()
        self.user_config = read_user_config_function(self.path)
        # Upgrade obsolete keys
        self.fixup_keys({'auto_cycle': 'auto_connect'})
        # Make a singleton instance of 'self'
        set_config(self)

    def electrum_path(self):
        # Read electrum_path from command line / system configuration
        # Otherwise use the user's default data directory.
        path = self.get('electrum_path')
        if path is None:
            path = self.user_dir()

        if self.get('testnet'):
            path = os.path.join(path, 'testnet')

        # Make directory if it does not yet exist.
        if not os.path.exists(path):
            if os.path.islink(path):
                raise BaseException('Dangling link: ' + path)
            os.mkdir(path)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        self.print_error("electrum directory", path)
        return path

    def fixup_config_keys(self, config, keypairs):
        updated = False
        for old_key, new_key in keypairs.items():
            if old_key in config:
                if not new_key in config:
                    config[new_key] = config[old_key]
                del config[old_key]
                updated = True
        return updated

    def fixup_keys(self, keypairs):
        '''Migrate old key names to new ones'''
        self.fixup_config_keys(self.cmdline_options, keypairs)
        self.fixup_config_keys(self.system_config, keypairs)
        if self.fixup_config_keys(self.user_config, keypairs):
            self.save_user_config()

    def set_key(self, key, value, save = True):
        if not self.is_modifiable(key):
            print_stderr("Warning: not changing config key '%s' set on the command line" % key)
            return

        with self.lock:
            self.user_config[key] = value
            if save:
                self.save_user_config()
        return

    def get(self, key, default=None):
        with self.lock:
            out = self.cmdline_options.get(key)
            if out is None:
                out = self.user_config.get(key)
                if out is None:
                    out = self.system_config.get(key, default)
        return out

    def is_modifiable(self, key):
        return not key in self.cmdline_options

    def save_user_config(self):
        if not self.path:
            return
        path = os.path.join(self.path, "config")
        s = json.dumps(self.user_config, indent=4, sort_keys=True)
        with open(path, "w") as f:
            f.write(s)
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)

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
        dirpath = os.path.join(self.path, "wallets")
        if not os.path.exists(dirpath):
            if os.path.islink(dirpath):
                raise BaseException('Dangling link: ' + dirpath)
            os.mkdir(dirpath)
            os.chmod(dirpath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

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
        f = self.get('max_fee_rate', MAX_FEE_RATE)
        if f==0:
            f = MAX_FEE_RATE
        return f

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
        return len(self.fee_estimates)==4

    def is_dynfee(self):
        return self.get('dynamic_fees', True)

    def fee_per_kb(self):
        dyn = self.is_dynfee()
        if dyn:
            fee_rate = self.dynfee(self.get('fee_level', 2))
        else:
            fee_rate = self.get('fee_per_kb', self.max_fee_rate()/2)
        return fee_rate

    def estimate_fee(self, size):
        return int(self.fee_per_kb() * size / 1000.)

    def update_fee_estimates(self, key, value):
        self.fee_estimates[key] = value
        self.fee_estimates_last_updated[key] = time.time()

    def is_fee_estimates_update_required(self):
        """Checks time since last requested and updated fee estimates.
        Returns True if an update should be requested.
        """
        now = time.time()
        prev_updates = self.fee_estimates_last_updated.values()
        oldest_fee_time = min(prev_updates) if prev_updates else 0
        stale_fees = now - oldest_fee_time > 7200
        old_request = now - self.last_time_fee_estimates_requested > 60
        return stale_fees and old_request

    def requested_fee_estimates(self):
        self.last_time_fee_estimates_requested = time.time()

    def get_video_device(self):
        device = self.get("video_device", "default")
        if device == 'default':
            device = ''
        return device


def read_system_config(path=SYSTEM_CONFIG_PATH):
    """Parse and return the system config settings in /etc/electrum.conf."""
    result = {}
    if os.path.exists(path):
        import configparser
        p = configparser.ConfigParser()
        try:
            p.read(path)
            for k, v in p.items('client'):
                result[k] = v
        except (configparser.NoSectionError, configparser.MissingSectionHeaderError):
            pass

    return result

def read_user_config(path):
    """Parse and store the user config settings in electrum.conf into user_config[]."""
    if not path:
        return {}
    config_path = os.path.join(path, "config")
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r") as f:
            data = f.read()
        result = json.loads(data)
    except:
        print_error("Warning: Cannot read config file.", config_path)
        return {}
    if not type(result) is dict:
        return {}
    return result
