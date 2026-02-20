from pythonforandroid.recipes.pyqt_builder import PyQtBuilderRecipe


assert PyQtBuilderRecipe._version == "1.19.1"
assert PyQtBuilderRecipe.depends == ["sip", "packaging", "python3"]
assert PyQtBuilderRecipe.python_depends == []


class PyQtBuilderRecipePinned(PyQtBuilderRecipe):
    sha512sum = "2308c51f93c37b1d13f312e4f2475d26b22d374ef284925fead9eab4aa89b994770431aca45170ac2154b4813fff151798f113f56d4cbf6c6e544fb463104a6d"

recipe = PyQtBuilderRecipePinned()
