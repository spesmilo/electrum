import os

from pythonforandroid.recipes.pyqt5sip import PyQt5SipRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt5SipRecipe._version == "12.9.0"
assert PyQt5SipRecipe.depends == ['setuptools', 'python3']
assert PyQt5SipRecipe.python_depends == []


class PyQt5SipRecipePinned(util.InheritedRecipeMixin, PyQt5SipRecipe):
    sha512sum = "ca6f3b18b64391fded88732a8109a04d85727bbddecdf126679b187c7f0487c3c1f69ada3e8c54051281a43c6f2de70390ac5ff18a1bed79994070ddde730c5f"


recipe = PyQt5SipRecipePinned()
