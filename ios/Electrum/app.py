#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
import os
from electrum.util import set_verbosity
from electrum_gui.ios_native import ElectrumGui
from electrum_gui.ios_native.utils import call_later, get_user_dir, cleanup_tmp_dir
from electrum.simple_config import SimpleConfig

def main():
    cleanup_tmp_dir()
    
    config_options = {
            'verbose': True,
            'cmd': 'gui',
            'gui': 'ios_native',
            'cwd': os.getcwd(),
    }

    set_verbosity(config_options.get('verbose'))

    for k,v in config_options.items():
        print("config[%s] = %s"%(str(k),str(v)))

    config = SimpleConfig(config_options, read_user_dir_function = get_user_dir)

    gui = ElectrumGui(config)
    gui.main()

    return "Bitcoin Cash FTW!"
