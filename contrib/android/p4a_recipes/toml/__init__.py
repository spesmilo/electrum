from pythonforandroid.recipes.toml import TomlRecipe


assert TomlRecipe._version == "0.10.2"
assert TomlRecipe.depends == ["setuptools", "python3"]
assert TomlRecipe.python_depends == []


class TomlRecipePinned(TomlRecipe):
    sha512sum = "ede2c8fed610a3827dba828f6e7ab7a8dbd5745e8ef7c0cd955219afdc83b9caea714deee09e853627f05ad1c525dc60426a6e9e16f58758aa028cb4d3db4b39"


recipe = TomlRecipePinned()
