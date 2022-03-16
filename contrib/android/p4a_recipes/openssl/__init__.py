import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    url_version = "1.1.1n"
    sha512sum = "1937796736613dcf4105a54e42ecb61f95a1cea74677156f9459aea0f2c95159359e766089632bf364ee6b0d28d661eb9957bce8fecc9d2436378d8d79e8d0a4"


recipe = OpenSSLRecipePinned()
