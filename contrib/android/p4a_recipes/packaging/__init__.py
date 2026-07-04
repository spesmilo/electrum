from pythonforandroid.recipes.packaging import PackagingRecipe
from pythonforandroid.util import HashPinnedDependency


assert PackagingRecipe._version == "26.0"
assert PackagingRecipe.depends == ["setuptools", "pyparsing", "python3"]
assert PackagingRecipe.python_depends == []


class PackagingRecipePinned(PackagingRecipe):
    sha512sum = "27a066a7d65ba76189212973b6a0d162f3d361848b1b0c34a82865cf180b3284a837cc34206c297f002a73feae414e25a26c5960bb884a74ea337f582585f1d2"
    hostpython_prerequisites = [
        HashPinnedDependency(package="flit-core==3.12.0",
                             hashes=['sha256:e7a0304069ea895172e3c7bb703292e992c5d1555dd1233ab7b5621b5b69e62c']),
    ]


recipe = PackagingRecipePinned()
