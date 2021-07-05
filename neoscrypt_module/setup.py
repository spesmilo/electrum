from setuptools import setup
from distutils.core import Extension
import platform

library_dirs = []
if platform.system() == 'Windows':
    library_dirs = ['c:\\python3.6.6']
    def get_msvcr():
        import sys
        msc_ver = sys.version.split('MSC v.')
        if len(msc_ver) == 2:
            if msc_ver[1][:4] == '1900':
                # for mapping see https://stackoverflow.com/questions/2676763/what-version-of-visual-studio-is-python-on-my-computer-compiled-with/2676904#2676904
                return ['vcruntime140']
            else:
                raise RuntimeError('Have you upgraded Python? Fix the vcruntime version!')

    from distutils import cygwinccompiler
    cygwinccompiler.get_msvcr = get_msvcr

neoscrypt_module = Extension('neoscrypt',
                             sources=['neoscrypt_module/neoscryptmodule.c',
                                      'neoscrypt_module/neoscrypt.c'],
                             library_dirs=library_dirs)

setup (name = 'neoscrypt',
       version = '1.0',
       description = 'Bindings for the NeoScrypt proof-of-work algorithm',
       author = 'John Doering',
       author_email = 'ghostlander@phoenixcoin.org',
       url = 'https://github.com/ghostlander/NeoScrypt',
       ext_modules = [neoscrypt_module])
