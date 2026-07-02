import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


# assert OpenSSLRecipe._version == "3.3.1"
assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    version = "3.0.21"
    sha512sum = "9be1c8c11a2d55417bb177804d1b5369aa54a9dcd2e136929509457d549697407ae9611079e94c61b58a95be598ce35b94edb336e050d1019e7269f4d2f52cda"


recipe = OpenSSLRecipePinned()
