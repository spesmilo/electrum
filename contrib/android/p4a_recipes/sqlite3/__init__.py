import os

from pythonforandroid.recipes.sqlite3 import Sqlite3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Sqlite3Recipe._version == "3.35.5"
assert Sqlite3Recipe.depends == []
assert Sqlite3Recipe.python_depends == []


class Sqlite3RecipePinned(util.InheritedRecipeMixin, Sqlite3Recipe):
    version = "3.54.1"
    url = 'https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip'
    sha512sum = "70a88503f1a4e287ed2d89157a0c23d9ecc162f2d4604659cea6f783b3c276dada5ee2bb8cbe967e4a2d9f2caba7f9b1529f66332158cb1e9727bf0a34d47f48"


recipe = Sqlite3RecipePinned()
