from pythonforandroid.recipes.pyqt_builder import PyQtBuilderRecipe


assert PyQtBuilderRecipe._version == "1.14.1"
assert PyQtBuilderRecipe.depends == ["sip", "packaging", "python3"]
assert PyQtBuilderRecipe.python_depends == []


class PyQtBuilderRecipePinned(PyQtBuilderRecipe):
    sha512sum = "4de9be2c42f38fbc22d46a31dd6da37c02620bb112a674ef846a4eb7f862715852e1d7328da1e0d0e33f78475166fe3c690e710e18bfeb48f840f137831a2182"


recipe = PyQtBuilderRecipePinned()
