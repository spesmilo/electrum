import os

from pythonforandroid.recipes.openssl import OpenSSLRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert OpenSSLRecipe._version == "3.3.1"
assert OpenSSLRecipe.depends == []
assert OpenSSLRecipe.python_depends == []


class OpenSSLRecipePinned(util.InheritedRecipeMixin, OpenSSLRecipe):
    sha512sum = "d3682a5ae0721748c6b9ec2f1b74d2b1ba61ee6e4c0d42387b5037a56ef34312833b6abb522d19400b45d807dd65cc834156f5e891cb07fbaf69fcf67e1c595d"


recipe = OpenSSLRecipePinned()
