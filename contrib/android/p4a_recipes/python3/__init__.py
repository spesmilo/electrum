import os

from pythonforandroid.recipes.python3 import Python3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Python3Recipe.depends == ['hostpython3', 'sqlite3', 'openssl', 'libffi']
assert Python3Recipe.python_depends == []


class Python3RecipePinned(util.InheritedRecipeMixin, Python3Recipe):
    version = "3.8.18"
    sha512sum = "2b98575763e21ba54428eb3e93418a3ea244f1dcdb4729ff0d17ac2d76cb45d228f0f97a2a24e59a7f0428234415e8bd129bbc0e8f2067bfd054d03df1641cf0"


recipe = Python3RecipePinned()
