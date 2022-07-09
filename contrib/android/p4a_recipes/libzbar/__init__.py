import os

from pythonforandroid.recipes.libzbar import LibZBarRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibZBarRecipe._version == "0.10"
assert LibZBarRecipe.depends == ['libiconv']
assert LibZBarRecipe.python_depends == []


class LibZBarRecipePinned(util.InheritedRecipeMixin, LibZBarRecipe):
    sha512sum = "d624f8ab114bf59c62e364f8b3e334bece48f5c11654739d810ed2b8553b8390a70763b0ae12d83c1472cfeda5d9e1a0b7c9c60228a79bf9f5a6fae4a9f7ccb9"


recipe = LibZBarRecipePinned()
