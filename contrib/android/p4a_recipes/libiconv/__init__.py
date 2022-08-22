import os

from pythonforandroid.recipes.libiconv import LibIconvRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibIconvRecipe._version == "1.15"
assert LibIconvRecipe.depends == []
assert LibIconvRecipe.python_depends == []


class LibIconvRecipePinned(util.InheritedRecipeMixin, LibIconvRecipe):
    sha512sum = "1233fe3ca09341b53354fd4bfe342a7589181145a1232c9919583a8c9979636855839049f3406f253a9d9829908816bb71fd6d34dd544ba290d6f04251376b1a"


recipe = LibIconvRecipePinned()
