import os

from pythonforandroid.recipes.libiconv import LibIconvRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibIconvRecipe._version == "1.16"
assert LibIconvRecipe.depends == []
assert LibIconvRecipe.python_depends == []


class LibIconvRecipePinned(util.InheritedRecipeMixin, LibIconvRecipe):
    version = "1.18"
    sha512sum = "a55eb3b7b785a78ab8918db8af541c9e11deb5ff4f89d54483287711ed797d87848ce0eafffa7ce26d9a7adb4b5a9891cb484f94bd4f51d3ce97a6a47b4c719a"


recipe = LibIconvRecipePinned()
