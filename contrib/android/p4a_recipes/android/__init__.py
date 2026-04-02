import os

from pythonforandroid.recipes.android import AndroidRecipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert AndroidRecipe.depends == [('sdl3', 'sdl2', 'genericndkbuild', 'qt6'), 'pyjnius', 'python3'], AndroidRecipe.depends
assert AndroidRecipe.python_depends == []


class AndroidRecipePinned(util.InheritedRecipeMixin, AndroidRecipe):
    hostpython_prerequisites = [
        HashPinnedDependency(package="Cython==3.1.8",
                             hashes=['sha256:282b3c8e6abc3fea421919e862e898ffdd86fc0796009bdb5ffdf8211413219f'])
    ]


recipe = AndroidRecipePinned()
