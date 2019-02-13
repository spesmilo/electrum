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
from electroncash_gui.ios_native.utils import call_later, get_user_dir, cleanup_tmp_dir, is_debug_build, NSLogSuppress
from electroncash.simple_config import SimpleConfig

def main():
    cleanup_tmp_dir()

    config_options = {
            'verbose': is_debug_build(),
            'cmd': 'gui',
            'gui': 'ios_native',
            'cwd': os.getcwd(),
    }

    set_verbosity(config_options.get('verbose'), timestamps=False)
    NSLogSuppress(not config_options.get('verbose'))

    MonkeyPatches.patch()

    #for k,v in config_options.items():
    #    print("config[%s] = %s"%(str(k),str(v)))

    config = SimpleConfig(config_options, read_user_dir_function = get_user_dir)

    gui = ElectrumGui(config)
    call_later(0.010, gui.main) # this is required for the activity indicator to actually animate. Switch to a direct call if not using activity indicator on Splash2

    return "Bitcoin Cash FTW!"
