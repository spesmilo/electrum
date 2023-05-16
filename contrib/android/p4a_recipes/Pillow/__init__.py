import os

from pythonforandroid.recipes.Pillow import PillowRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PillowRecipe._version == "7.0.0"
assert PillowRecipe.depends == ['png', 'jpeg', 'freetype', 'setuptools', 'python3']
assert PillowRecipe.python_depends == []


class PillowRecipePinned(util.InheritedRecipeMixin, PillowRecipe):
    sha512sum = "187173a525d4f3f01b4898633263b53a311f337aa7b159c64f79ba8c7006fd44798a058e7cc5d8f1116bad008e4142ff303456692329fe73b0e115ef5c225d73"


recipe = PillowRecipePinned()
