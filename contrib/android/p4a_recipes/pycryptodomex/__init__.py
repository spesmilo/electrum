from pythonforandroid.recipe import PythonRecipe


assert PythonRecipe.depends == ['python3']
assert PythonRecipe.python_depends == []


class PycryptodomexRecipe(PythonRecipe):
    version = "3.23.0"
    sha512sum = "951cebaad2e19b9f9d04fe85c73ab1ff8b515069c1e0e8e3cd6845ec9ccd5ef3e5737259e0934ed4a6536e289dee6aabac58e1c822a5a6393e86b482c60afc89"
    url = "https://github.com/Legrandin/pycryptodome/archive/v{version}x.tar.gz"
    depends = ["setuptools", "cffi"]


recipe = PycryptodomexRecipe()
