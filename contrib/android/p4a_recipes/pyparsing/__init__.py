from pythonforandroid.recipes.pyparsing import PyparsingRecipe


assert PyparsingRecipe._version == "3.0.7"
assert PyparsingRecipe.depends == ["setuptools", "python3"]
assert PyparsingRecipe.python_depends == []


class PyparsingRecipePinned(PyparsingRecipe):
    #version = "3.0.7"
    # note: 3.0.7 is the last version to use setup.py, so newer versions don't work,
    #       as p4a runs "$ python3 setup.py install". This is only going become a larger problem, needs fix upstream.
    #       see https://github.com/kivy/python-for-android/blob/be3de2e28e5a52d5f8949f3969f8a3b7f9eb3cba/pythonforandroid/recipe.py#L983
    #       - but maybe upstream p4a already has a workaround?
    #         see "PyProjectRecipe" from https://github.com/kivy/python-for-android/pull/3007
    sha512sum = "1e692f4cdaa6b6e8ca2729d0a3e2ba16d978f1957c538b6de3a4220ec7d996bdbe87c41c43abab851fffa3b0498a05841373e435602917b8c095042e273badb5"


recipe = PyparsingRecipePinned()
