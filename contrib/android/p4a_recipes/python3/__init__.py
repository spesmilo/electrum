import os

from pythonforandroid.recipes.python3 import Python3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert Python3Recipe.depends == ['hostpython3', 'sqlite3', 'openssl', 'libffi']
assert Python3Recipe.python_depends == []


class Python3RecipePinned(util.InheritedRecipeMixin, Python3Recipe):
    # PYTHON_VERSION=    # < line here so that I can grep the codebase and teleport here
    version = "3.11.18"
    sha512sum = "b4e532d6dfa59757facf684739bea7db320f25eb5df16d90acb132a1b62e00374b76a085ba5d42bdfec457e9db28fe1e32274627613cf745be29f4f7345ba140"

    # use official releases from python.org that have sigs, instead of auto-generated archives from github
    url = 'https://www.python.org/ftp/python/{version}/Python-{version}.tgz'


recipe = Python3RecipePinned()
