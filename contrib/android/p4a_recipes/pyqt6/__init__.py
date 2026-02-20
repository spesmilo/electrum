import os

from pythonforandroid.recipes.pyqt6 import PyQt6Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt6Recipe._version == "6.10.1"
assert PyQt6Recipe.depends == ['qt6', 'pyjnius', 'setuptools', 'pyqt6sip', 'hostpython3', 'python3'], PyQt6Recipe.depends
assert PyQt6Recipe.python_depends == []


class PyQt6RecipePinned(util.InheritedRecipeMixin, PyQt6Recipe):
    sha512sum = "af9bb54b20fd177cf1dac5fe8fb0ff289e1e7e42716d09093d49dd99a7d8065c6b6f34784ed19e21e7e07ba0d550b270cb6be7273f7180e2bf886160fc773d01"


recipe = PyQt6RecipePinned()
