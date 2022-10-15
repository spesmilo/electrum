from pythonforandroid.recipes.pyqt_builder import PyQtBuilderRecipe


assert PyQtBuilderRecipe._version == "1.12.2"
assert PyQtBuilderRecipe.depends == ["sip", "packaging", "python3"]
assert PyQtBuilderRecipe.python_depends == []


class PyQtBuilderRecipePinned(PyQtBuilderRecipe):
    sha512sum = "022f2cd40c100543c4b442fc5b27bbf2ec853d94b531f8f6dc1d7f92b07bcc20e8f0a4eb64feb96d094ba0d5f01fddcc8aed23ddf67a61417e07983a73918230"


recipe = PyQtBuilderRecipePinned()
