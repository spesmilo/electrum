import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    version = "3.8.16"
    sha512sum = "59940a0f646e9ec320c3ee40b1a960da6418e4365ba05c179f36235a3a50fd151ddd5f5d295c40ab291a9e7cb760abe1f61511a2460336f08189297d1c22f09c"


recipe = HostPython3RecipePinned()
