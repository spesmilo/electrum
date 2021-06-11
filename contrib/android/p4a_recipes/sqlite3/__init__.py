import os

from pythonforandroid.recipes.sqlite3 import Sqlite3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Sqlite3Recipe._version == "3.34.1"
assert Sqlite3Recipe.depends == []
assert Sqlite3Recipe.python_depends == []


class Sqlite3RecipePinned(util.InheritedRecipeMixin, Sqlite3Recipe):
    sha512sum = "8a936f1c34fc9036cadf5bd53f9ee594135c2efdef1d2c82bd4fdf3e0218afde710fc4c436cfc992687d008e6086a697da0487352ed88809d677e05d824940dd"


recipe = Sqlite3RecipePinned()
