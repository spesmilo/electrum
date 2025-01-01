import os

from pythonforandroid.recipes.pyqt6 import PyQt6Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt6Recipe._version == "6.4.2"
assert PyQt6Recipe.depends == ['qt6', 'pyjnius', 'setuptools', 'pyqt6sip', 'hostpython3', 'pyqt_builder']
assert PyQt6Recipe.python_depends == []


class PyQt6RecipePinned(util.InheritedRecipeMixin, PyQt6Recipe):
    sha512sum = "51e5f0d028ee7984876da1653cb135d61e2c402f18b939a92477888cc7c86d3bc2889477403dee6b3d9f66519ee3236d344323493b4c2c2e658e1637b10e53bf"


recipe = PyQt6RecipePinned()
