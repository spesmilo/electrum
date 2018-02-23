from distutils.core import setup, Extension

neoscrypt_module = Extension('neoscrypt',
                               sources = ['neoscryptmodule.c',
                                          'neoscrypt.c'],
                               include_dirs=['.'])

setup (name = 'neoscrypt',
       version = '1.0',
       description = 'Bindings for the NeoScrypt proof-of-work algorithm',
       author = 'John Doering',
       author_email = 'ghostlander@phoenixcoin.org',
       url = 'https://github.com/ghostlander/NeoScrypt',
       ext_modules = [neoscrypt_module])
