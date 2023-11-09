from pythonforandroid.recipes.tomli import TomliRecipe


assert TomliRecipe._version == "2.0.1"
assert TomliRecipe.depends == ["setuptools", "python3"]
assert TomliRecipe.python_depends == []


class TomliRecipePinned(TomliRecipe):
    sha512sum = "fd410039e255e2b3359e999d69a5a2d38b9b89b77e8557f734f2621dfbd5e1207e13aecc11589197ec22594c022f07f41b4cfe486a3a719281a595c95fd19ecf"


recipe = TomliRecipePinned()
