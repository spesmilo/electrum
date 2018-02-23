from setuptools import setup
from distutils.core import Extension

neoscrypt_module = Extension('neoscrypt',
                             sources=['neoscrypt_module/neoscryptmodule.c',
                                      'neoscrypt_module/neoscrypt.c'],
                             )

setup (name = 'neoscrypt',
       version = '1.0',
       description = 'Bindings for the NeoScrypt proof-of-work algorithm',
       author = 'John Doering',
       author_email = 'ghostlander@phoenixcoin.org',
       url = 'https://github.com/ghostlander/NeoScrypt',
       ext_modules = [neoscrypt_module])
