from pythonforandroid.recipes.pycparser import PycparserRecipe
from pythonforandroid.util import HashPinnedDependency


assert PycparserRecipe._version == "2.14"
assert PycparserRecipe.depends == ['setuptools', 'python3']
assert PycparserRecipe.python_depends == []


class PycparserRecipePinned(PycparserRecipe):
    version = "3.12"
    sha512sum = "59ff647f5e902b275b53e9abfad84d1791832be49800ffda82115dd12d0fa780800c163cb12109e247bc6507fa9d58a585edf46e7a614e820c8d0b4335d60a06"
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = PycparserRecipePinned()
