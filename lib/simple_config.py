import json, ast
import os, ast
from util import user_dir, print_error

from version import ELECTRUM_VERSION, SEED_VERSION



class SimpleConfig:
    """
The SimpleConfig class is responsible for handling operations involving
configuration files.  The constructor reads and stores the system and 
user configurations from electrum.conf into seperate dictionaries within
a SimpleConfig instance then reads the wallet file.
"""
    def __init__(self, options={}):

        # system conf, readonly
        self.system_config = {}
        if options.get('portable') == False:
            self.read_system_config()

        # user conf, writeable
        self.user_dir = user_dir()
        self.user_config = {}
        if options.get('portable') == False:
            self.read_user_config()

        # command-line options
        self.options_config = options

        self.wallet_config = {}
        self.wallet_file_exists = False
        self.init_path(self.options_config.get('wallet_path'))
        print_error( "path", self.path )
        if self.path:
            self.read_wallet_config(self.path)

        # portable wallet: use the same directory for wallet and headers file
        if options.get('portable'):
            self.wallet_config['blockchain_headers_path'] = os.path.dirname(self.path)
            
            
        

    def set_key(self, key, value, save = False):
        # find where a setting comes from and save it there
        if self.options_config.get(key) is not None:
            print "Warning: not changing '%s' because it was passed as a command-line option"%key
            return

        elif self.user_config.get(key) is not None:
            self.user_config[key] = value
            if save: self.save_user_config()

        elif self.system_config.get(key) is not None:
            if str(self.system_config[key]) != str(value):
                print "Warning: not changing '%s' because it was set in the system configuration"%key

        elif self.wallet_config.get(key) is not None:
            self.wallet_config[key] = value
            if save: self.save_wallet_config()

        else:
            # add key to wallet config
            self.wallet_config[key] = value
            if save: self.save_wallet_config()


    def get(self, key, default=None):
        """Retrieve the filepath of the configuration file specified in the 'key' parameter."""
        # 1. command-line options always override everything
        if self.options_config.has_key(key) and self.options_config.get(key) is not None:
            out = self.options_config.get(key)

        # 2. user configuration 
        elif self.user_config.has_key(key):
            out = self.user_config.get(key)

        # 2. system configuration
        elif self.system_config.has_key(key):
            out = self.system_config.get(key)

        # 3. use the wallet file config
        else:
            out = self.wallet_config.get(key)

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
        if not self.user_dir: return

        name = os.path.join( self.user_dir, 'electrum.conf')
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
                    self.user_config[k] = v
            except ConfigParser.NoSectionError:
                pass

    def init_path(self, path):
        """Set the path of the wallet."""

        if not path:
            path = self.get('default_wallet_path')

        if path is not None:
            self.path = path
            return

        # Look for wallet file in the default data directory.
        # Make wallet directory if it does not yet exist.
        if not os.path.exists(self.user_dir):
            os.mkdir(self.user_dir)
        self.path = os.path.join(self.user_dir, "electrum.dat")


    def save_user_config(self):
        if not self.user_dir: return

        import ConfigParser
        config = ConfigParser.RawConfigParser()
        config.add_section('client')
        for k,v in self.user_config.items():
            config.set('client', k, v)

        with open( os.path.join( self.user_dir, 'electrum.conf'), 'wb') as configfile:
            config.write(configfile)
        



    def read_wallet_config(self, path):
        """Read the contents of the wallet file."""
        try:
            with open(self.path, "r") as f:
                data = f.read()
        except IOError:
            return
        try:
            d = ast.literal_eval( data )  #parse raw data from reading wallet file
        except:
            raise IOError("Cannot read wallet file.")

        self.wallet_config = d
        self.wallet_file_exists = True



    def save(self, key=None):
        self.save_wallet_config()


    def save_wallet_config(self):
        # prevent the creation of incomplete wallets  
        if self.wallet_config.get('master_public_key') is None: 
            return

        s = repr(self.wallet_config)
        f = open(self.path,"w")
        f.write( s )
        f.close()
        if self.get('gui') != 'android':
            import stat
            os.chmod(self.path,stat.S_IREAD | stat.S_IWRITE)

