from pythonforandroid.recipes.packaging import PackagingRecipe


assert PackagingRecipe._version == "21.3"
assert PackagingRecipe.depends == ["setuptools", "pyparsing", "python3"]
assert PackagingRecipe.python_depends == []


class PackagingRecipePinned(PackagingRecipe):
    #version = "21.3"
    # note: 21.3 is the last version to use setup.py, so newer versions don't work. see comment for PyparsingRecipePinned
    sha512sum = "2e3aa276a4229ac7dc0654d586799473ced9761a83aa4159660d37ae1a2a8f30e987248dd0e260e2834106b589f259a57ce9936eef0dcc3c430a99ac6b663e05"


recipe = PackagingRecipePinned()
