import os

from pythonforandroid.recipes.pyqt6sip import PyQt6SipRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt6SipRecipe._version == "13.10.3"
assert PyQt6SipRecipe.depends == ['setuptools', 'python3']
assert PyQt6SipRecipe.python_depends == []


class PyQt6SipRecipePinned(util.InheritedRecipeMixin, PyQt6SipRecipe):
    sha512sum = "555b061eec3db6a66388fae07de21f58d756f6f12b13e4ede729c3348d2c8997ac5a59d3006ee45c3a09b5cde673f579265fa254bc583a4ba721748cf8f3a617"


recipe = PyQt6SipRecipePinned()
