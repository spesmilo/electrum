from pythonforandroid.recipe import PythonRecipe


assert PythonRecipe.depends == ['python3']
assert PythonRecipe.python_depends == []


class CertifiRecipePinned(PythonRecipe):
    version = "2023.11.17"
    sha512sum = "e359b4062d42e19ce6d16b25c17696f09ff5c35e7c92626b4eb15130cfa55941817db456d1c27d1188e0a6ff5f52db37607c0b15c1e438da3ea6d514c0d3443e"
    url = "https://pypi.python.org/packages/source/c/certifi/certifi-{version}.tar.gz"
    depends = ["setuptools"]


recipe = CertifiRecipePinned()
