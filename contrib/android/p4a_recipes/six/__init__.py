from pythonforandroid.recipes.six import SixRecipe


assert SixRecipe._version == "1.15.0"
assert SixRecipe.depends == ['setuptools', 'python3']
assert SixRecipe.python_depends == []


class SixRecipePinned(SixRecipe):
    version = "1.17.0"
    sha512sum = "fcfa58b03877ac3ac00a4f85b5fea4fecb2a010244451aa95013637a0aa21529f3dcfe25c0a07c72da46da1fa12bc0c16b6c641c40c6ab2133e5b5cbb5a71e4b"


recipe = SixRecipePinned()
