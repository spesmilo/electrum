from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.util import HashPinnedDependency

assert PythonRecipe.depends == ['python3']
assert PythonRecipe.python_depends == []


class PycryptodomexRecipe(PythonRecipe):
    version = "3.23.0"
    sha512sum = "951cebaad2e19b9f9d04fe85c73ab1ff8b515069c1e0e8e3cd6845ec9ccd5ef3e5737259e0934ed4a6536e289dee6aabac58e1c822a5a6393e86b482c60afc89"
    url = "https://github.com/Legrandin/pycryptodome/archive/v{version}x.tar.gz"
    depends = ["cffi"]
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = PycryptodomexRecipe()
