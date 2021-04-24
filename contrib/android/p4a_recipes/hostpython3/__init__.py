import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    version = "3.8.8"
    sha512sum = "1c6742cdc92ba6d3c03c63fd025bc348462517a503343685a42e22838aedc94ab2e438f1d1623b91ca1be5f39f327d76385d66b785ff93f0f3737b9870e9a003"


recipe = HostPython3RecipePinned()
