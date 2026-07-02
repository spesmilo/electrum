import os

from pythonforandroid.recipes.python3 import Python3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Python3Recipe.depends == ['hostpython3', 'sqlite3', 'openssl', 'libffi']
assert Python3Recipe.python_depends == []


class Python3RecipePinned(util.InheritedRecipeMixin, Python3Recipe):
    # PYTHON_VERSION=    # < line here so that I can grep the codebase and teleport here
    version = "3.11.15"
    sha512sum = "d4b4d9c51412dca47f0259ad351d4630d4d26fccbbe1457cc8e2168a7b2cbbd43113c1b5a64efe62d0e81f81c31c6f28109696e8633bc0943ad4cb9eb9340bbb"

    # use official releases from python.org that have sigs, instead of auto-generated archives from github
    url = 'https://www.python.org/ftp/python/{version}/Python-{version}.tgz'


recipe = Python3RecipePinned()
