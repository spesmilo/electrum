from pythonforandroid.recipe import PythonRecipe


assert PythonRecipe.depends == ['python3']
assert PythonRecipe.python_depends == []


class PlyerRecipePinned(PythonRecipe):
    version = "2.0.0"
    sha512sum = "8088eeb41aac753435ff5be9835be74d57a55cf557ad76cbad8026352647e554571fae6172754e39882ea7ef07cc1e97fac16556a4426456de99daebe5cd01cf"
    url = "https://pypi.python.org/packages/source/p/plyer/plyer-{version}.tar.gz"
    depends = ["setuptools"]


recipe = PlyerRecipePinned()
