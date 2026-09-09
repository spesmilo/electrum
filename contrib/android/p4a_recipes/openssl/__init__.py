import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


# assert OpenSSLRecipe._version == "3.3.1"
assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    version = "3.0.22"
    sha512sum = "88f5cffd8949b9e236f989f414eefcd4e924145b9e8cb303a969534908e055a9ff2a4b29bd1619425c84240d9ae40aab0d84dbee0f338d20fac81cf7b2f20492"


recipe = OpenSSLRecipePinned()
