import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    version = "3.10.14"
    sha512sum = "113d8faf2685a7a9e868e4c0ecb2767aae3e54a8d3722a2de5ca00049b336c8728a6a6506b282326d94acc71a5c534ea706ad7b886a6ec7d15eaf46505ef233b"


recipe = HostPython3RecipePinned()
