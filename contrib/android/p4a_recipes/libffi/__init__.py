import os

from pythonforandroid.recipes.libffi import LibffiRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibffiRecipe._version == "v3.4.2"
assert LibffiRecipe.depends == []
assert LibffiRecipe.python_depends == []


class LibffiRecipePinned(util.InheritedRecipeMixin, LibffiRecipe):
    version = "v3.8.0"
    sha512sum = "798302568c6b40742d0b08f3e4c56a6acb33175d222e0dc18fb4ef806d8e7517e8d98f9e18617e6256587eb6fea3f3fd4074bda6359193ba953d0ca92a1dae02"


recipe = LibffiRecipePinned()
