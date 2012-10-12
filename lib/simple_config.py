import json, ast
import os, ast
from util import user_dir

from version import ELECTRUM_VERSION, SEED_VERSION


# old stuff.. should be removed at some point
def replace_keys(obj, old_key, new_key):
    if isinstance(obj, dict):
        if old_key in obj:
            obj[new_key] = obj[old_key]
            del obj[old_key]
        for elem in obj.itervalues():
            replace_keys(elem, old_key, new_key)
    elif isinstance(obj, list):
        for elem in obj:
            replace_keys(elem, old_key, new_key)

def old_to_new(d):
    replace_keys(d, 'blk_hash', 'block_hash')
    replace_keys(d, 'pos', 'index')
    replace_keys(d, 'nTime', 'timestamp')
    replace_keys(d, 'is_in', 'is_input')
    replace_keys(d, 'raw_scriptPubKey', 'raw_output_script')



class SimpleConfig:

    def __init__(self, options):

        self.wallet_config = {}
        self.read_wallet_config(options.wallet_path)

        self.common_config = {}
        self.read_common_config()

        self.options_config = {}

        if options.server: self.options_config['server'] = options.server
        if options.proxy: self.options_config['proxy'] = options.proxy
        if options.gui: self.options_config['gui'] = options.gui
        
        

    def set_key(self, key, value, save = False):
        # find where a setting comes from and save it there
        if self.options_config.get(key):
            return

        elif self.wallet_config.get(key):
            self.wallet_config[key] = value
            if save: self.save_wallet_config()

        elif self.common_config.get(key):
            self.common_config[key] = value
            if save: self.save_common_config()

        else:
            # add key to wallet config
            self.wallet_config[key] = value
            if save: self.save_wallet_config()


    def get(self, key, default=None):
        # 1. command-line options always override everything
        if self.options_config.has_key(key):
            # print "found", key, "in options"
            out = self.options_config.get(key)

        # 2. configuration file overrides wallet file
        elif self.common_config.has_key(key):
            out = self.common_config.get(key)
            
        else:
            out = self.wallet_config.get(key)

        if out is None and default is not None:
            out = default
        return out


    def is_modifiable(self, key):
        if self.options_config.has_key(key) or self.common_config.has_key(key):
            return False
        else:
            return True


    def read_common_config(self):
        for name in ['/etc/electrum.conf', os.path.join( user_dir(), 'electrum.conf')]:
            if os.path.exists(name):
                try:
                    import ConfigParser
                except:
                    print "cannot parse electrum.conf. please install ConfigParser"
                    return
                
                p = ConfigParser.ConfigParser()
                p.read(name)
                for k, v in p.items('client'):
                    self.common_config[k] = v




    def init_path(self, wallet_path):
        """Set the path of the wallet."""
        if wallet_path is not None:
            self.path = wallet_path
            return

        # Look for wallet file in the default data directory.
        # Keeps backwards compatibility.
        wallet_dir = user_dir()

        # Make wallet directory if it does not yet exist.
        if not os.path.exists(wallet_dir):
            os.mkdir(wallet_dir)
        self.path = os.path.join(wallet_dir, "electrum.dat")



    def save_common_config(self):
        s = repr(self.common_config)
        # todo: decide what to do 
        print "not saving settings in common config:", s



    def read_wallet_config(self, path):
        """Read the contents of the wallet file."""
        self.wallet_file_exists = False
        self.init_path(path)
        try:
            with open(self.path, "r") as f:
                data = f.read()
        except IOError:
            return
        try:
            d = ast.literal_eval( data )  #parse raw data from reading wallet file
            old_to_new(d)
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

