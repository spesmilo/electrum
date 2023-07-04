import os

from pythonforandroid.recipes.qt6 import Qt6Recipe

from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))

assert Qt6Recipe._version == "6.4.3"
assert Qt6Recipe.depends == ['python3', 'hostqt6']
assert Qt6Recipe.python_depends == []

class Qt6RecipePinned(util.InheritedRecipeMixin, Qt6Recipe):
    sha512sum = "767d2d388dab64ba314743841b9b2dbd68996876d15621e0ae97688e2ef1300c70f96b417bf111f119c87699a3d7014c70aec3a80b5216212bb5d35979230db7"


recipe = Qt6RecipePinned()
