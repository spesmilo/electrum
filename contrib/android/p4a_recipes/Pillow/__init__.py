import os

from pythonforandroid.recipes.Pillow import PillowRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PillowRecipe._version == "8.4.0"
assert PillowRecipe.depends == ['png', 'jpeg', 'freetype', 'setuptools', 'python3']
assert PillowRecipe.python_depends == []


class PillowRecipePinned(util.InheritedRecipeMixin, PillowRecipe):
    sha512sum = "d395f69ccb37c52a3b6f45836700ffbc3173afae31848cc61d7b47db88ca1594541023beb9a14fd9067aca664e182c7d6e3300ab3e3095c31afe8dcbc6e08233"


recipe = PillowRecipePinned()
