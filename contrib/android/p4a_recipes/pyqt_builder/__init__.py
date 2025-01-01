from pythonforandroid.recipes.pyqt_builder import PyQtBuilderRecipe


assert PyQtBuilderRecipe._version == "1.15.1"
assert PyQtBuilderRecipe.depends == ["sip", "packaging", "python3"]
assert PyQtBuilderRecipe.python_depends == []


class PyQtBuilderRecipePinned(PyQtBuilderRecipe):
    sha512sum = "61ee73b6bb922c04739da60025ab50d35d345d2e298943305fcbd3926cda31d732cc5e5b0dbfc39f5eb85c0f0b091b8c3f5fee00dcc240d7849c5c4191c1368a"


recipe = PyQtBuilderRecipePinned()
