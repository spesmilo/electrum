import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


# assert OpenSSLRecipe._version == "3.3.1"
assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    version = "3.5.9"
    sha512sum = "c4c8136fd2c98d13bb85a57bfb0def25c906f47f1fe97675cd114594944eab957b5b81a3e0f48826e1a0f093afff5e83766b539d49768f6db68310fd678d7de6"


recipe = OpenSSLRecipePinned()
