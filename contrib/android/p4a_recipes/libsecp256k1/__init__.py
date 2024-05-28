from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "e3a885d42a7800c1ccebad94ad1e2b82c4df5c65"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "fef2671fcdcf9a1127597b2db0109279c38053b990bd3b979f863fdb3c92e691df9e2d3bdd22e1bb59100b3d27f27b07df1f0e314f2535148bd250665c8f1370"


recipe = LibSecp256k1RecipePinned()
