import os

from pythonforandroid.recipes.png import PngRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PngRecipe._version == "1.6.37"
assert PngRecipe.depends == []
assert PngRecipe.python_depends == []


class PngRecipePinned(util.InheritedRecipeMixin, PngRecipe):
    sha512sum = "f304f8aaaee929dbeff4ee5260c1ab46d231dcb0261f40f5824b5922804b6b4ed64c91cbf6cc1e08554c26f50ac017899a5971190ca557bc3c11c123379a706f"


recipe = PngRecipePinned()
