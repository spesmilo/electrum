import os

from pythonforandroid.recipes.cffi import CffiRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert CffiRecipe._version == "1.15.1"
assert CffiRecipe.depends == ['setuptools', 'pycparser', 'libffi', 'python3']
assert CffiRecipe.python_depends == []


class CffiRecipePinned(util.InheritedRecipeMixin, CffiRecipe):
    version = "1.17.1"
    sha512sum = "907129891d56351ca5cb885aae62334ad432321826d6eddfaa32195b4c7b7689a80333e6d14d0aab479a646aba148b9852c0815b80344dfffa4f183a5e74372c"


recipe = CffiRecipePinned()
