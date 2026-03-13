import os

from pythonforandroid.recipes.pyjnius import PyjniusRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyjniusRecipe._version == "1.7.0"
assert PyjniusRecipe.depends == [('genericndkbuild', 'sdl2', 'sdl3', 'qt6'), 'six', 'python3'], PyjniusRecipe.depends
assert PyjniusRecipe.python_depends == []


class PyjniusRecipePinned(util.InheritedRecipeMixin, PyjniusRecipe):
    sha512sum = "a192c30ef87ca9601455976feb49f03dfdb8e1bf2545744a7b771a6d0930a56b334c7a2a39d30fb8855c070f16e4673dc5ff6920b04a6155ab5f9247b271df76"


recipe = PyjniusRecipePinned()
