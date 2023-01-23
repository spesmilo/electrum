import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    url_version = "1.1.1s"
    sha512sum = "2ef983f166b5e1bf456ca37938e7e39d58d4cd85e9fc4b5174a05f5c37cc5ad89c3a9af97a6919bcaab128a8a92e4bdc8a045e5d9156d90768da8f73ac67c5b9"


recipe = OpenSSLRecipePinned()
