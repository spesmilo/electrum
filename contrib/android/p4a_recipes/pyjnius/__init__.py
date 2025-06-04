import os

from pythonforandroid.recipes.pyjnius import PyjniusRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyjniusRecipe._version == "1.5.0"
assert PyjniusRecipe.depends == [('genericndkbuild', 'sdl2', 'qt6'), 'six', 'python3']
assert PyjniusRecipe.python_depends == []


class PyjniusRecipePinned(util.InheritedRecipeMixin, PyjniusRecipe):
    version = "1.6.1"
    sha512sum = "deb5ac566479111c6f4c6adb895821b263d72bf88414fb093bdfd5ad5d0b7aea56b53d5ef0967e28db360f4fb6fb1c2264123f15c747884799df55848191c424"


recipe = PyjniusRecipePinned()
