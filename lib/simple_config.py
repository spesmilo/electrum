import json, ast
import os, ast
from util import user_dir, print_error

from version import ELECTRUM_VERSION, SEED_VERSION



class SimpleConfig:

    def __init__(self, options=None):

        # system conf, readonly
        self.system_config = {}
        self.read_system_config()

        # user conf, writeable
        self.user_config = {}
        self.read_user_config()

        # command-line options
        self.options_config = {}
        if options:
            if options.server: self.options_config['server'] = options.server
            if options.proxy: self.options_config['proxy'] = options.proxy
            if options.gui: self.options_config['gui'] = options.gui


        self.wallet_config = {}
        self.wallet_file_exists = False
        self.init_path(options)
        print_error( "path", self.path )
        if self.path:
            self.read_wallet_config(self.path)
            
            
        

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
        # 1. command-line options always override everything
        if self.options_config.has_key(key):
            # print "found", key, "in options"
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
                print "type error, using default value"
                out = default

        return out


    def is_modifiable(self, key):
        if self.options_config.has_key(key):
            return False
        elif self.user_config.has_key(key):
            return True
        elif self.system_config.has_key(key):
            return False
        else:
            return True


    def read_system_config(self):
        name = '/etc/electrum.conf'
        if os.path.exists(name):
            try:
                import ConfigParser
            except:
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
        name = os.path.join( user_dir(), 'electrum.conf')
        if os.path.exists(name):
            try:
                import ConfigParser
            except:
                print "cannot parse electrum.conf. please install ConfigParser"
                return
                
            p = ConfigParser.ConfigParser()
            p.read(name)
            try:
                for k, v in p.items('client'):
                    self.user_config[k] = v
            except ConfigParser.NoSectionError:
                pass


    def init_path(self, options):
        """Set the path of the wallet."""

        path = None
        if options:
            # this will call read_wallet_config only if there is a wallet_path value in options
            try:
                path = options.wallet_path
            except:
                pass

        if not path:
            path = self.get('default_wallet_path')

        if path is not None:
            self.path = path
            return

        # Look for wallet file in the default data directory.
        # Keeps backwards compatibility.
        wallet_dir = user_dir()

        # Make wallet directory if it does not yet exist.
        if not os.path.exists(wallet_dir):
            os.mkdir(wallet_dir)
        self.path = os.path.join(wallet_dir, "electrum.dat")


    def save_user_config(self):
        import ConfigParser
        config = ConfigParser.RawConfigParser()
        config.add_section('client')
        for k,v in self.user_config.items():
            config.set('client', k, v)

        with open( os.path.join( user_dir(), 'electrum.conf'), 'wb') as configfile:
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



    def save(self):
        self.save_wallet_config()


    def save_wallet_config(self):
        s = repr(self.wallet_config)
        f = open(self.path,"w")
        f.write( s )
        f.close()
        import stat
        os.chmod(self.path,stat.S_IREAD | stat.S_IWRITE)

