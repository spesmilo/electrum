import os

from pythonforandroid.recipes.pyqt6 import PyQt6Recipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt6Recipe._version == "6.10.2"
assert PyQt6Recipe.depends == ['qt6', 'pyjnius', 'setuptools', 'pyqt6sip', 'hostpython3', 'pyqt_builder', 'python3'], PyQt6Recipe.depends
assert PyQt6Recipe.python_depends == []


class PyQt6RecipePinned(util.InheritedRecipeMixin, PyQt6Recipe):
    sha512sum = "d58515d181530fdd71edc3edfa0b647a3aeeb56cbc33f4d7fd0d40a7a99d52298ac5bb4438b5dadea5439759e52cc459e601f1fab5d9afdd61f2a492d0bae1ef"
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = PyQt6RecipePinned()
