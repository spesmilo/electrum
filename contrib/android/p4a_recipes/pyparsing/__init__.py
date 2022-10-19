from pythonforandroid.recipes.pyparsing import PyparsingRecipe


assert PyparsingRecipe._version == "3.0.7"
assert PyparsingRecipe.depends == ["setuptools", "python3"]
assert PyparsingRecipe.python_depends == []


class PyparsingRecipePinned(PyparsingRecipe):
    sha512sum = "1e692f4cdaa6b6e8ca2729d0a3e2ba16d978f1957c538b6de3a4220ec7d996bdbe87c41c43abab851fffa3b0498a05841373e435602917b8c095042e273badb5"


recipe = PyparsingRecipePinned()
