import os

from pythonforandroid.recipes.qt6 import Qt6Recipe

from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))

assert Qt6Recipe._version == "6.4.3"
assert Qt6Recipe.depends == ['python3', 'hostqt6']
assert Qt6Recipe.python_depends == []

class Qt6RecipePinned(util.InheritedRecipeMixin, Qt6Recipe):
    sha512sum = "0bdbe8b9a43390c98cf19e851ec5394bc78438d227cf9d0d7a3748aee9a32a7f14fc46f52d4fa283819f21413567080aee7225c566af5278557f5e1992674da3"


recipe = Qt6RecipePinned()
