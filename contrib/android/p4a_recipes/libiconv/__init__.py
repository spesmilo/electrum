import os

from pythonforandroid.recipes.libiconv import LibIconvRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibIconvRecipe._version == "1.16"
assert LibIconvRecipe.depends == []
assert LibIconvRecipe.python_depends == []


class LibIconvRecipePinned(util.InheritedRecipeMixin, LibIconvRecipe):
    sha512sum = "365dac0b34b4255a0066e8033a8b3db4bdb94b9b57a9dca17ebf2d779139fe935caf51a465d17fd8ae229ec4b926f3f7025264f37243432075e5583925bb77b7"


recipe = LibIconvRecipePinned()
