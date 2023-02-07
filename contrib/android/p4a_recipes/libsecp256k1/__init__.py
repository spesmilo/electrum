from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "21ffe4b22a9683cf24ae0763359e401d1284cc7a"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "51832bfc6825690d5b71a5426aacce8981163ca1a56a235394aa86e742d105f5e2b331971433a21b8842ee338cbd7877dcbae5605fa01a9e6f4a73171b93f3e9"


recipe = LibSecp256k1RecipePinned()
