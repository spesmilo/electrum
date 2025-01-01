from pythonforandroid.recipe import PythonRecipe


assert PythonRecipe.depends == ['python3']
assert PythonRecipe.python_depends == []


class PlyerRecipePinned(PythonRecipe):
    version = "5262087c85b2c82c69e702fe944069f1d8465fdf"
    url = "git+https://github.com/SomberNight/plyer"
    depends = ["setuptools"]


recipe = PlyerRecipePinned()
