import os

from pythonforandroid.recipes.sdl2 import LibSDL2Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibSDL2Recipe._version == "2.0.9"
assert LibSDL2Recipe.depends == ['sdl2_image', 'sdl2_mixer', 'sdl2_ttf']
assert LibSDL2Recipe.python_depends == []


class LibSDL2RecipePinned(util.InheritedRecipeMixin, LibSDL2Recipe):
    md5sum = None
    sha512sum = "a78a4708b2bb5b35a7c7b7501eb3bd60a9aa3bb95a3d84e57763df4a377185e7312a94b66321eef7ca0d17255e4b402fc950e83ef0dbbd08f14ff1194107dc10"


recipe = LibSDL2RecipePinned()
