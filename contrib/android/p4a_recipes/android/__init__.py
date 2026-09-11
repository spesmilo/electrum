import os

from pythonforandroid.recipes.android import AndroidRecipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert AndroidRecipe.depends == [('sdl3', 'sdl2', 'genericndkbuild', 'qt6'), 'pyjnius', 'python3'], AndroidRecipe.depends
assert AndroidRecipe.python_depends == []


class AndroidRecipePinned(util.InheritedRecipeMixin, AndroidRecipe):
    hostpython_prerequisites = [
        # note: cython ships no pure-python wheel, so this hash is specific to
        #       the cpython version hostpython3 is pinned to. Update on bumps.
        HashPinnedDependency(package="Cython==3.1.8",
                             hashes=['sha256:0bc71b05497608c1f8dc99340055c0456f712ce8a1cf35391c9134bbd037f7c6'])
    ]


recipe = AndroidRecipePinned()
