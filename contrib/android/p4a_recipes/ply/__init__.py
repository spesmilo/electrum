import os

from pythonforandroid.recipes.ply import PlyRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PlyRecipe._version == "3.11"
assert PlyRecipe.depends == ['packaging', 'python3']
assert PlyRecipe.python_depends == []


class PlyRecipePinned(util.InheritedRecipeMixin, PlyRecipe):
    sha512sum = "37e39a4f930874933223be58a3da7f259e155b75135f1edd47069b3b40e5e96af883ebf1c8a1bbd32f914a9e92cfc12e29fec05cf61b518f46c1d37421b20008"


recipe = PlyRecipePinned()
