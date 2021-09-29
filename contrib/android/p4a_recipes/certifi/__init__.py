from pythonforandroid.recipe import PythonRecipe


assert PythonRecipe.depends == ['python3']
assert PythonRecipe.python_depends == []


class CertifiRecipePinned(PythonRecipe):
    version = "2020.12.5"
    sha512sum = "3425d98f19025e70d885458629071c8531271d93d1461fadea6afbaafc763881a42b3c05be391a938d84a0d1ab729c3ac5df4f3328e8ef63a7b56ead1445bddd"
    url = "https://pypi.python.org/packages/source/c/certifi/certifi-{version}.tar.gz"
    depends = ["setuptools"]


recipe = CertifiRecipePinned()
