import os

from pythonforandroid.recipes.libffi import LibffiRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibffiRecipe._version == "v3.3"
assert LibffiRecipe.depends == []
assert LibffiRecipe.python_depends == []


class LibffiRecipePinned(util.InheritedRecipeMixin, LibffiRecipe):
    sha512sum = "62798fb31ba65fa2a0e1f71dd3daca30edcf745dc562c6f8e7126e54db92572cc63f5aa36d927dd08375bb6f38a2380ebe6c5735f35990681878fc78fc9dbc83"


recipe = LibffiRecipePinned()
