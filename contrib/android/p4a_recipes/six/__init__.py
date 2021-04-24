from pythonforandroid.recipes.six import SixRecipe


assert SixRecipe._version == "1.15.0"
assert SixRecipe.depends == ['setuptools', 'python3']
assert SixRecipe.python_depends == []


class SixRecipePinned(SixRecipe):
    sha512sum = "eb840ac17f433f1fc4af56de75cfbfe0b54e6a737bb23c453bf09a4a13d768d153e46064880dc763f4c5cc2785b78ea6d3d3b4a41fed181cb9064837e3f699a9"


recipe = SixRecipePinned()
