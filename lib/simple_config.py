import json, ast
import os, ast
from util import user_dir, print_error

from version import ELECTRUM_VERSION, SEED_VERSION






class SimpleConfig:
    """
The SimpleConfig class is responsible for handling operations involving
configuration files.  The constructor reads and stores the system and 
user configurations from electrum.conf into separate dictionaries within
a SimpleConfig instance then reads the wallet file.
"""
    def __init__(self, options={}):

        # system conf, readonly
        self.system_config = {}
        if options.get('portable') is not True:
            self.read_system_config()

        # read path
        self.path = self.system_config.get('electrum_path')
        if self.path is None:
            self.path = user_dir()

        # user conf, writeable
        self.user_config = {}
        if options.get('portable') == False:
            self.read_user_config()

        # command-line options
        self.options_config = options

        # init path
        self.init_path()

        print_error( "electrum path", self.path)


    def init_path(self):

        # Look for wallet file in the default data directory.
        # Make wallet directory if it does not yet exist.
        if not os.path.exists(self.path):
            os.mkdir(self.path)


        # portable wallet: use the same directory for wallet and headers file
        #if options.get('portable'):
        #    self.wallet_config['blockchain_headers_path'] = os.path.dirname(self.path)
            
    def set_key(self, key, value, save = True):
        # find where a setting comes from and save it there
        if self.options_config.get(key) is not None:
            print "Warning: not changing '%s' because it was passed as a command-line option"%key
            return

        elif self.system_config.get(key) is not None:
            if str(self.system_config[key]) != str(value):
                print "Warning: not changing '%s' because it was set in the system configuration"%key

        else:
            self.user_config[key] = value
            if save: self.save_user_config()



    def get(self, key, default=None):

        out = None

        # 1. command-line options always override everything
        if self.options_config.has_key(key) and self.options_config.get(key) is not None:
            out = self.options_config.get(key)

        # 2. user configuration 
        elif self.user_config.has_key(key):
            out = self.user_config.get(key)

        # 2. system configuration
        elif self.system_config.has_key(key):
            out = self.system_config.get(key)

        if out is None and default is not None:
            out = default

        # try to fix the type
        if default is not None and type(out) != type(default):
            import ast
            try:
                out = ast.literal_eval(out)
            except:
                print "type error for '%s': using default value"%key
                out = default

        return out


    def is_modifiable(self, key):
        """Check if the config file is modifiable."""
        if self.options_config.has_key(key):
            return False
        elif self.user_config.has_key(key):
            return True
        elif self.system_config.has_key(key):
            return False
        else:
            return True


    def read_system_config(self):
        """Parse and store the system config settings in electrum.conf into system_config[]."""
        name = '/etc/electrum.conf'
        if os.path.exists(name):
            try:
                import ConfigParser
            except ImportError:
                print "cannot parse electrum.conf. please install ConfigParser"
                return
                
            p = ConfigParser.ConfigParser()
            p.read(name)
            try:
                for k, v in p.items('client'):
                    self.system_config[k] = v
            except ConfigParser.NoSectionError:
                pass


    def read_user_config(self):
        """Parse and store the user config settings in electrum.conf into user_config[]."""
        if not self.path: return

        path = os.path.join(self.path, "config")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = f.read()
            except IOError:
                return
            try:
                d = ast.literal_eval( data )  #parse raw data from reading wallet file
            except:
                raise IOError("Cannot read config file.")

            self.user_config = d


    def save_user_config(self):
        if not self.path: return

        path = os.path.join(self.path, "config")
        s = repr(self.user_config)
        f = open(path,"w")
        f.write( s )
        f.close()
        if self.get('gui') != 'android':
            import stat
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
