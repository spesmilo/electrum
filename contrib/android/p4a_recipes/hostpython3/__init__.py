import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    # PYTHON_VERSION=    # < line here so that I can grep the codebase and teleport here
    version = "3.11.14"
    sha512sum = "4642f6d59c76c6e5dbd827fdb28694376a9cc76e513146d092b49afb41513b3c9dff2339cfcebfb5b260f5cdc49a59a69906e284e5d478b2189d3374e9e24fd5"


recipe = HostPython3RecipePinned()
