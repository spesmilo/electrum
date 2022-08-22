import os

from pythonforandroid.recipes.python3 import Python3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Python3Recipe.depends == ['hostpython3', 'sqlite3', 'openssl', 'libffi']
assert Python3Recipe.python_depends == []


class Python3RecipePinned(util.InheritedRecipeMixin, Python3Recipe):
    version = "3.8.13"
    sha512sum = "e57f5f5b441e46a742b0147dd7fbfa6b52d550a86e60c9765ecc3c4690e2cdedf197e151c07cd2ea1f75ed9022a2b8ce4850c3d65916eaede1db6feed40b52f6"


recipe = Python3RecipePinned()
