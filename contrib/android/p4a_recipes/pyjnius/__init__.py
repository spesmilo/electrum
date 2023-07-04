import os

from pythonforandroid.recipes.pyjnius import PyjniusRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyjniusRecipe._version == "1.5.0"
assert PyjniusRecipe.depends == [('genericndkbuild', 'sdl2', 'qt6'), 'six', 'python3']
assert PyjniusRecipe.python_depends == []


class PyjniusRecipePinned(util.InheritedRecipeMixin, PyjniusRecipe):
    sha512sum = "e47ff08bdcda8fc9ef9617fc84515a85404d77cfce3ede3e190ae21221837a4275840e14976271f38eb5d514682d22eab5d83d8ca94dbf3a6b47d4effa109790"


recipe = PyjniusRecipePinned()
