import os

from pythonforandroid.recipes.sqlite3 import Sqlite3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Sqlite3Recipe._version == "3.35.5"
assert Sqlite3Recipe.depends == []
assert Sqlite3Recipe.python_depends == []


class Sqlite3RecipePinned(util.InheritedRecipeMixin, Sqlite3Recipe):
    version = "3.50.0"
    url = 'https://www.sqlite.org/2025/sqlite-amalgamation-3500000.zip'
    sha512sum = "0fd87f2b8140300ce165600f6708aafef19041a181e9f00ed14f7aeaa3c06805c8c54c53751a9ce74d4d666f018ca6f48e3f5b5c874ccb9e1424a528c92326f0"


recipe = Sqlite3RecipePinned()
