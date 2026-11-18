import os

from pythonforandroid.recipes.android import AndroidRecipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert AndroidRecipe.depends == [('sdl3', 'sdl2', 'genericndkbuild'), 'pyjnius', 'python3'], AndroidRecipe.depends
assert AndroidRecipe.python_depends == []


class AndroidRecipePinned(util.InheritedRecipeMixin, AndroidRecipe):
    # build-system requirements of the recipe's pyproject.toml
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
        HashPinnedDependency(package="wheel==0.45.1",
                             hashes=['sha256:708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248']),
        # the pure-python wheel: the other wheels are specific to the python version of hostpython3
        HashPinnedDependency(package="Cython==3.1.8",
                             hashes=['sha256:f36368c1d7ea4003c52e9e93f3556074a631a6482f8a32e781cb073e211e4df9'])
    ]


recipe = AndroidRecipePinned()
