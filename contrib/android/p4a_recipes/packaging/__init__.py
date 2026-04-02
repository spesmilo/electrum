from pythonforandroid.recipes.packaging import PackagingRecipe


assert PackagingRecipe._version == "26.0"
assert PackagingRecipe.depends == ["setuptools", "pyparsing", "python3"]
assert PackagingRecipe.python_depends == []


class PackagingRecipePinned(PackagingRecipe):
    sha512sum = "27a066a7d65ba76189212973b6a0d162f3d361848b1b0c34a82865cf180b3284a837cc34206c297f002a73feae414e25a26c5960bb884a74ea337f582585f1d2"


recipe = PackagingRecipePinned()
