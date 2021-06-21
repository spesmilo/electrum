import os

from pythonforandroid.recipes.sdl2_image import LibSDL2Image
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibSDL2Image._version == "2.0.4"
assert LibSDL2Image.depends == []
assert LibSDL2Image.python_depends == []


class LibSDL2ImageRecipePinned(util.InheritedRecipeMixin, LibSDL2Image):
    sha512sum = "7320a5c9111908d402fbb0c12a49eb359a6db645c0c86839793ebb1a5b75eaca7c85eb96851f3a0b4a68a2f06363c8189555afd4f1048a4a41447370eddd7e6a"


recipe = LibSDL2ImageRecipePinned()
