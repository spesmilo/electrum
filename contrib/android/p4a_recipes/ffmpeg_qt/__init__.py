import os

from pythonforandroid.recipes.ffmpeg_qt import FFmpegQtRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))

assert FFmpegQtRecipe._version == "7.1.5"
assert FFmpegQtRecipe.depends == []
assert FFmpegQtRecipe.python_depends == []


class FFmpegQtRecipePinned(util.InheritedRecipeMixin, FFmpegQtRecipe):
    sha512sum = "c0649ef9edd4176b90459e92b636be18077ca898f24fe1a8dc60f3c5fd58cf718db9720bbe804c6f6894453e21c0625d706ea37d3523fcb40d61779763d7d965"


recipe = FFmpegQtRecipePinned()
