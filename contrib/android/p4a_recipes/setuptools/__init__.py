from pythonforandroid.recipes.setuptools import SetuptoolsRecipe
from pythonforandroid.util import HashPinnedDependency


assert SetuptoolsRecipe._version == "80.9.0"
assert SetuptoolsRecipe.depends == ['python3']
assert SetuptoolsRecipe.python_depends == []


class SetuptoolsRecipePinned(SetuptoolsRecipe):
    sha512sum = "36eb1f219d29c6b9e135936bde2001ad70a971c8069cd0175d3a5325b450e6843a903d3f70043c9f534768ebeab8ab0c544b8f44456555d333f1ed72daa5c18b"
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = SetuptoolsRecipePinned()
