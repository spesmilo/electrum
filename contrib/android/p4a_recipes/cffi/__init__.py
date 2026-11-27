import os

from pythonforandroid.recipes.cffi import CffiRecipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert CffiRecipe._version == "2.0.0"
assert CffiRecipe.depends == ['pycparser', 'libffi', 'python3'], CffiRecipe.depends
assert CffiRecipe.python_depends == []


class CffiRecipePinned(util.InheritedRecipeMixin, CffiRecipe):
    version = "2.1.1"
    sha512sum = "86af9771c4f8f0bfb129e63cb263dbaf2f32bb755e056fa04bc4cdd32eee4392634a866dd930263e6eeb011f81ee2bd90f9e6602adf016c80e124bdbfbb62c38"
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = CffiRecipePinned()
