import os

from pythonforandroid.recipes.cffi import CffiRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert CffiRecipe._version == "1.13.2"
assert CffiRecipe.depends == ['setuptools', 'pycparser', 'libffi', 'python3']
assert CffiRecipe.python_depends == []


class CffiRecipePinned(util.InheritedRecipeMixin, CffiRecipe):
    sha512sum = "2c57d9c06c39e95498a54408dc39940427190f3c03e1b8f1a3584140db08a5775dd12e6e67b03093429c130af579d01519b0fc868b99ba7a530068ed22d38522"


recipe = CffiRecipePinned()
