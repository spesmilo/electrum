#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT License
#
import os
# Disable google protobuf C++ implementation since we don't have the .so files
# anyway on iOS.  this call isn't strictly necessary but we may as well
# do it just to be sure.
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

# The below line needs to be here becasue the iOS main.m evaluates this script and looks for a
# Python class (that is bridged to ObjC) named "PythonAppDelegate", which gets the
# 'applicationDidFinishLaunchingWithOptions' call, which is really where we start the app.
import electroncash_gui.ios_native.appdelegate
from electroncash_gui.ios_native.uikit_bindings import *
import sys


if __name__ == '__main__':
    C_like_argv = [sys.executable] + sys.argv  # prepend executable path to follow C argv convention
    argc = c_int(len(C_like_argv))
    argv = (c_char_p * (argc.value + 1))()
    for i,a in enumerate(C_like_argv):
        argv[i] = c_char_p(a.encode('utf-8'))
    argv[-1] = 0  # This actually sets last pointer to NULL, and not int(0)

    #.argtypes = [c_int, POINTER(c_char_p), c_void_p, c_void_p]
    uikit.UIApplicationMain(argc, argv, None, ns_from_py("PythonAppDelegate").ptr)
    sys.exit(0) # ensure we don't end up back in Obj-C's main.m
    # at this point process exits.. note that the Briefcase auto-generated main.m invocation of UIApplicationMain will not end up being called!
