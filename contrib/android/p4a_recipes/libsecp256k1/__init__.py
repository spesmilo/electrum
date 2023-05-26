from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "acf5c55ae6a94e5ca847e07def40427547876101"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "6639f239de3c7abc1906088f2b0bf833b3c7b073bc25151fa908a64b5585dce59a073ed4eb0c0c3360c785a639ca4fce897e0288b94bbfa7f1d07f7ab610f1d6"


recipe = LibSecp256k1RecipePinned()
