import os

from pythonforandroid.recipes.pyqt6sip import PyQt6SipRecipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt6SipRecipe._version == "13.10.3"
assert PyQt6SipRecipe.depends == ['python3']
assert PyQt6SipRecipe.python_depends == []


class PyQt6SipRecipePinned(util.InheritedRecipeMixin, PyQt6SipRecipe):
    sha512sum = "555b061eec3db6a66388fae07de21f58d756f6f12b13e4ede729c3348d2c8997ac5a59d3006ee45c3a09b5cde673f579265fa254bc583a4ba721748cf8f3a617"

    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
        HashPinnedDependency(package="packaging==26.0",
                             hashes=['sha256:b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529']),
    ]


recipe = PyQt6SipRecipePinned()
