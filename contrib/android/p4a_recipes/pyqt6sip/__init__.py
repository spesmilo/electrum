import os

from pythonforandroid.recipes.pyqt6sip import PyQt6SipRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt6SipRecipe._version == "13.5.1"
assert PyQt6SipRecipe.depends == ['setuptools', 'python3']
assert PyQt6SipRecipe.python_depends == []


class PyQt6SipRecipePinned(util.InheritedRecipeMixin, PyQt6SipRecipe):
    sha512sum = "1e4170d167a326afe6df86e4a35e209299548054981cb2e5d56da234ef9db4d8594bcb05b6be363c3bc6252776ae9de63d589a3d9f33fba8250d39cdb5e9061a"


recipe = PyQt6SipRecipePinned()
