import os
import sys


def is_android():
    return 'ANDROID_DATA' in os.environ


def is_linux():
    # android is linux, but we don't want to match here
    return sys.platform == 'linux' and not is_android()


def is_windows():
    return sys.platform in ['win32', 'windows']  # not sure if 'windows' can still occur.


def is_mac():
    return sys.platform == 'darwin'


def is_appimage():
    return 'APPIMAGE' in os.environ and is_linux()
