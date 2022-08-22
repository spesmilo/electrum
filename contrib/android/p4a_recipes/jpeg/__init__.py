import os

from pythonforandroid.recipes.jpeg import JpegRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert JpegRecipe._version == "2.0.1"
assert JpegRecipe.depends == []
assert JpegRecipe.python_depends == []


class JpegRecipePinned(util.InheritedRecipeMixin, JpegRecipe):
    sha512sum = "d456515dcda7c5e2e257c9fd1441f3a5cff0d33281237fb9e3584bbec08a181c4b037947a6f87d805977ec7528df39b12a5d32f6e8db878a62bcc90482f86e0e"


recipe = JpegRecipePinned()
