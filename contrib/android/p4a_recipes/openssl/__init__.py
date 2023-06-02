import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    url_version = "1.1.1t"
    sha512sum = "628676c9c3bc1cf46083d64f61943079f97f0eefd0264042e40a85dbbd988f271bfe01cd1135d22cc3f67a298f1d078041f8f2e97b0da0d93fe172da573da18c"


recipe = OpenSSLRecipePinned()
