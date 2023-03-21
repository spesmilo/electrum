import os

from pythonforandroid.recipes.pyqt5 import PyQt5Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt5Recipe._version == "5.15.9"
assert PyQt5Recipe.depends == ['qt5', 'pyjnius', 'setuptools', 'pyqt5sip', 'hostpython3', 'pyqt_builder']
assert PyQt5Recipe.python_depends == []


class PyQt5RecipePinned(util.InheritedRecipeMixin, PyQt5Recipe):
    sha512sum = "1c07d93aefe1c24e80851eb4631b80a99e7ba06e823181325456edb90285d3d22417a9f7d4c3ff9c6195bd801e7dc2bbabf0587af844a5e4b0a410c4611d119e"


recipe = PyQt5RecipePinned()
