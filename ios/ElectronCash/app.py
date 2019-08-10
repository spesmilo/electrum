#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
import os
from electroncash_gui.ios_native.monkeypatches import MonkeyPatches
from electroncash.util import set_verbosity
from electroncash_gui.ios_native import ElectrumGui
from electroncash_gui.ios_native.utils import call_later, get_user_dir, cleanup_tmp_dir, is_debug_build, NSLogSuppress, NSLog
from electroncash.simple_config import SimpleConfig
from electroncash.networks import set_mainnet, set_testnet

# NB: This is called from appdelegate.py "application_didFinishLaunchingWithOptions_"
def main():
    cleanup_tmp_dir()

    config_options = {
            'verbose': is_debug_build(),
            'cmd': 'gui',
            'gui': 'ios_native',
            'cwd': os.getcwd(),
            'whitelist_servers_only' : True,  # on iOS we force only the whitelist ('preferred') servers only for now as a security measure
            'testnet': 'EC_TESTNET' in os.environ,  # You can set the env when testing using Xcode "Scheme" editor
    }

    if config_options.get('testnet'):
        set_testnet()
    else:
        set_mainnet()

    set_verbosity(config_options.get('verbose'), timestamps=False, thread_id=False)
    NSLogSuppress(not config_options.get('verbose'))

    MonkeyPatches.patch()

    config = SimpleConfig(config_options, read_user_dir_function = get_user_dir)

    gui = ElectrumGui(config)
    call_later(0.010, gui.main) # this is required for the activity indicator to actually animate. Switch to a direct call if not using activity indicator on Splash2

    _printStats(config_options)  # Prints some startup/debug stats such as Python version and SSL version (this is done in another thread to hopefully not impact startup overhead too much, as importing ssl may be a bit heavy)

    return "Bitcoin Cash FTW!"

def _printStats(config_options):
    import threading
    def thrdfunc(config_options):
        # lazy init of SSL
        import ssl, sys
        from electroncash import version, ecc_fast, schnorr
        NSLog("Electron Cash lib version: %s (using server protocol: %s)", version.PACKAGE_VERSION, version.PROTOCOL_VERSION)
        NSLog("Python version: %s", ' '.join(sys.version.split('\n')))
        NSLog("OpenSSL version: %s", ssl.OPENSSL_VERSION)
        NSLog("Fast ECC: %s  Fast Schnorr: %s", str(ecc_fast.is_using_fast_ecc()), str(schnorr.has_fast_sign()))
        #NSLog("Environment Vars:")
        #for k,v in os.environ.copy().items():
        #    NSLog("%s=%s", str(k), str(v))
        #NSLog("Config Vars:")
        #for k,v in config_options.copy().items():
        #    NSLog("config[%s] = %s", str(k), str(v))
    # /
    # We do this from a thread so as to not delay app startup by importing more stuff we don't strictly need.
    threading.Thread(target=thrdfunc, args=(config_options,), daemon=True).start()
