import os

from pythonforandroid.recipes.pyjnius import PyjniusRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyjniusRecipe._version == "1.4.2"
assert PyjniusRecipe.depends == [('genericndkbuild', 'sdl2', 'qt5'), 'six', 'python3']
assert PyjniusRecipe.python_depends == []


class PyjniusRecipePinned(util.InheritedRecipeMixin, PyjniusRecipe):
    sha512sum = "3cf1637f96b71398977c9608ead7261115f198e79de7c601fb86b984fc2c7f193910f14869ea249819211d13249947a632eb1bbf5edb66b98738edbf79acabc7"


recipe = PyjniusRecipePinned()
