from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "a660a4976efe880bae7982ee410b9e0dc59ac983"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "13f8f9d51fba5a38f591d770c7f39a1266a041be59a850d83cf62fb0de0274ed3a34c56ba8393d6f611e522cdbd798cb7ccbb2a6b03f2e5898a3b1080ea01874"


recipe = LibSecp256k1RecipePinned()
