import os

from pythonforandroid.recipes.qt6 import Qt6Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))

assert Qt6Recipe._version == "6.10.1"
assert Qt6Recipe.depends == ['python3', 'hostqt6']
assert Qt6Recipe.python_depends == []


class Qt6RecipePinned(util.InheritedRecipeMixin, Qt6Recipe):
    sha512sum = "62e8a8fcdef84187bff43e6185a1ba983e3db4d927ec01cd0ff5247d12eb7fd116a8f67323b3e44ba23f2e1792ade8c54e033cf28f34ec42a776ec204b9c2d8d"


recipe = Qt6RecipePinned()
