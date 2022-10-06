import os

from pythonforandroid.recipes.libffi import LibffiRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibffiRecipe._version == "v3.4.2"
assert LibffiRecipe.depends == []
assert LibffiRecipe.python_depends == []


class LibffiRecipePinned(util.InheritedRecipeMixin, LibffiRecipe):
    sha512sum = "d399319efcca375fe901b05722e25eca31d11a4261c6a5d5079480bbc552d4e4b42de2026912689d3b2f886ebb3c8bebbea47102e38a2f6acbc526b8d5bba388"


recipe = LibffiRecipePinned()
