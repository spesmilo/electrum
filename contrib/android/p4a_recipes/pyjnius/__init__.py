import os

from pythonforandroid.recipes.pyjnius import PyjniusRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyjniusRecipe._version == "1.3.0"
assert PyjniusRecipe.depends == [('genericndkbuild', 'sdl2'), 'six', 'python3']
assert PyjniusRecipe.python_depends == []


class PyjniusRecipePinned(util.InheritedRecipeMixin, PyjniusRecipe):
    sha512sum = "5a3475afcda5afbef6e1a67bab508e3c24bd564efda5ac38ae7669d39b4bfdbfaaa83f435f26d39b3d849d3a167a9c136c9ac6b2bfcc0bda09ef1c00aa66cf25"


recipe = PyjniusRecipePinned()
