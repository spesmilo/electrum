import os

from pythonforandroid.recipes.pyqt5sip import PyQt5SipRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt5SipRecipe._version == "12.11.1"
assert PyQt5SipRecipe.depends == ['setuptools', 'python3']
assert PyQt5SipRecipe.python_depends == []


class PyQt5SipRecipePinned(util.InheritedRecipeMixin, PyQt5SipRecipe):
    sha512sum = "9a24b6e8356fdb1070672ee37e5f4259d72a75bb60376ad0946274331ae29a6cceb98a6c5a278bf5e8015a3d493c925bacab8593ef02c310ff3773bd3ee46a5d"


recipe = PyQt5SipRecipePinned()
