import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert OpenSSLRecipe._version == "3.0.18"
assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    version = "3.0.18"
    sha512sum = "6bdd16f33b83ae2a12777230c4ff00d0595bbc00253ac8c3ac31e1375e818fc74d7f491bd2e507ff33cab9f0498cfb28fa8690f75a98663568d40901523cdf3c"


recipe = OpenSSLRecipePinned()
