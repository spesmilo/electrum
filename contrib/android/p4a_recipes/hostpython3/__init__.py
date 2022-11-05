import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    version = "3.8.15"
    sha512sum = "625af8fa23e7a7daba6302d147ccf80da36b8b5cce7a99976583bf8e07f1ca71c11529b6286e7732d69c00398dfa8422243f33641e2164e4299237663103ae99"


recipe = HostPython3RecipePinned()
