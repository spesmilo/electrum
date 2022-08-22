import os

from pythonforandroid.recipes.pyqt5 import PyQt5Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt5Recipe._version == "5.15.6"
assert PyQt5Recipe.depends == ['qt5', 'pyjnius', 'setuptools', 'pyqt5sip']
assert PyQt5Recipe.python_depends == []


class PyQt5RecipePinned(util.InheritedRecipeMixin, PyQt5Recipe):
    sha512sum = "65fd663cb70e8701e49bd4b39dc9384546cf2edd1b3bab259ca64b50908f48bdc02ca143f36cd6b429075f5616dcc7b291607dcb63afa176e828cded3b82f5c7"


recipe = PyQt5RecipePinned()
