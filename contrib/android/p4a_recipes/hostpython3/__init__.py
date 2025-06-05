import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    version = "3.10.18"
    sha512sum = "494a76de4e92122b9722240d6c33a3e2345072240e0b60938010bc6da34ec7ff7961f329585c140cb6ea0a254d987f1e4b1a678ba9ec7d8feeb8bb262be65a06"


recipe = HostPython3RecipePinned()
