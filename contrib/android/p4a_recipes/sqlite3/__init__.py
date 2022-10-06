import os

from pythonforandroid.recipes.sqlite3 import Sqlite3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Sqlite3Recipe._version == "3.35.5"
assert Sqlite3Recipe.depends == []
assert Sqlite3Recipe.python_depends == []


class Sqlite3RecipePinned(util.InheritedRecipeMixin, Sqlite3Recipe):
    sha512sum = "9684fee89224f0c975c280cb6b2c64adb040334bc5517dfe0e354b0557459fa3ae642c4289a7a5265f65b3ad5b6747db8068a1e5172fbb8edec7f6d964ecbb20"


recipe = Sqlite3RecipePinned()
