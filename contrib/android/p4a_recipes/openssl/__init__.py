import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


# assert OpenSSLRecipe._version == "3.3.1"
assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    version = "3.5.8"
    sha512sum = "62a1dbed0fad75245b332e41b85a1f7c2379189525e7628a7cf68947d115e90a47f179e3f87d27641e5b2d357c357292179fc0e64eccecdebc81c083f7a8ebe4"


recipe = OpenSSLRecipePinned()
