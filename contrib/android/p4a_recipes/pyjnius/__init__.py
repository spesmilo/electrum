import os

from pythonforandroid.recipes.pyjnius import PyjniusRecipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyjniusRecipe._version == "1.7.0"
assert PyjniusRecipe.depends == [('genericndkbuild', 'sdl2', 'sdl3', 'qt6'), 'six', 'python3'], PyjniusRecipe.depends
assert PyjniusRecipe.python_depends == []


class PyjniusRecipePinned(util.InheritedRecipeMixin, PyjniusRecipe):
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
        HashPinnedDependency(package="wheel==0.45.1",
                             hashes=['sha256:708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248']),
        HashPinnedDependency(package="Cython==3.1.8",
                             hashes=['sha256:282b3c8e6abc3fea421919e862e898ffdd86fc0796009bdb5ffdf8211413219f'])
    ]

    sha512sum = "a192c30ef87ca9601455976feb49f03dfdb8e1bf2545744a7b771a6d0930a56b334c7a2a39d30fb8855c070f16e4673dc5ff6920b04a6155ab5f9247b271df76"


recipe = PyjniusRecipePinned()
