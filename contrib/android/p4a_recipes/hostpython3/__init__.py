import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    # PYTHON_VERSION=    # < line here so that I can grep the codebase and teleport here
    version = "3.11.14"
    sha512sum = "41fb3ae22ce4ac0e8bb6b9ae8db88a810af1001d944e3f1abc9e86824ae4be31347e3e3a70425ab12271c6b7eeef552f00164ef23cfffa2551c3c9d1fe5ab91f"


recipe = HostPython3RecipePinned()
