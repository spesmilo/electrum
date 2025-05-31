import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    version = "3.10.17"
    sha512sum = "26d06125edab989755f3ddc1e0ab4e5816d3e1d3ab6f92d2f48a5d1c2f7d4538bdbdecaac9141e9e84241e1a7809ffc8126b6f400e3abb7f867882a222448791"


recipe = HostPython3RecipePinned()
