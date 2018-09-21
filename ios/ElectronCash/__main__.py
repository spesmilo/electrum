#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#

# The below line needs to be here becasue the iOS main.m evaluates this script and looks for a
# Python class (that is bridged to ObjC) named "PythonAppDelegate", which gets the
# 'applicationDidFinishLaunchingWithOptions' call, which is really where we start the app.
import electroncash_gui.ios_native.appdelegate
from electroncash_gui.ios_native.uikit_bindings import *
import sys


if __name__ == '__main__':
    argc = c_int(len(sys.argv))
    argv = (c_char_p * (argc.value + 1))()
    for i,a in enumerate(sys.argv):
        argv[i] = c_char_p(a.encode('utf-8'))
    argv[-1] = 0

    #.argtypes = [c_int, POINTER(c_char_p), c_void_p, c_void_p]
    uikit.UIApplicationMain(argc, argv, None, ns_from_py("PythonAppDelegate").ptr)
    sys.exit(0) # ensure we don't end up back in Obj-C's main.m
    # at this point process exits.. note that the Briefcase auto-generated main.m invocation of UIApplicationMain will not end up being called!
