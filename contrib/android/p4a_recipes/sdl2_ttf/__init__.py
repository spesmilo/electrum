import os

from pythonforandroid.recipes.sdl2_ttf import LibSDL2TTF
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibSDL2TTF._version == "2.0.15"
assert LibSDL2TTF.depends == []
assert LibSDL2TTF.python_depends == []


class LibSDL2TTFPinned(util.InheritedRecipeMixin, LibSDL2TTF):
    sha512sum = "30d685932c3dd6f2c94e2778357a5c502f0421374293d7102a64d92f9c7861229bf36bedf51c1a698b296a58c858ca442d97afb908b7df1592fc8d4f8ae8ddfd"


recipe = LibSDL2TTFPinned()
