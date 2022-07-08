import os

from pythonforandroid.recipes.freetype import FreetypeRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert FreetypeRecipe._version == "2.10.1"
assert FreetypeRecipe.depends == []
assert FreetypeRecipe.python_depends == []


class FreetypeRecipePinned(util.InheritedRecipeMixin, FreetypeRecipe):
    sha512sum = "346c682744bcf06ca9d71265c108a242ad7d78443eff20142454b72eef47ba6d76671a6e931ed4c4c9091dd8f8515ebdd71202d94b073d77931345ff93cfeaa7"


recipe = FreetypeRecipePinned()
