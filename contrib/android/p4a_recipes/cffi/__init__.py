import os

from pythonforandroid.recipes.cffi import CffiRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert CffiRecipe._version == "1.15.1"
assert CffiRecipe.depends == ['setuptools', 'pycparser', 'libffi', 'python3']
assert CffiRecipe.python_depends == []


class CffiRecipePinned(util.InheritedRecipeMixin, CffiRecipe):
    sha512sum = "e99cafcb029076abc29e435b490fa0573ee2856f4051b7ca8a5b38cd125d56dd9dae8b189f59ceb3d728a675da8ee83239e09e19f8b0feeddea4b186ab5173a5"


recipe = CffiRecipePinned()
