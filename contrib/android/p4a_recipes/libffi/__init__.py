import os

from pythonforandroid.recipes.libffi import LibffiRecipe
from pythonforandroid.util import load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert LibffiRecipe._version == "v3.4.2"
assert LibffiRecipe.depends == []
assert LibffiRecipe.python_depends == []


class LibffiRecipePinned(util.InheritedRecipeMixin, LibffiRecipe):
    version = "v3.4.8"
    sha512sum = "064a43ddae005f3d0fa56db4da6071fae93aaae87a755b84888c0cb9c8fa2fe9bb452b3d9a382fab64c442c19d98a20ba15b8be92eba7bf3773815b31fb7824c"


recipe = LibffiRecipePinned()
