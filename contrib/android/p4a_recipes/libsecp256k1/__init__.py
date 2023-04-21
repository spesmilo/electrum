from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "346a053d4c442e08191f075c3932d03140579d47"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "d6232bd8fb29395984b15633bee582e7588ade0ec1c7bea5b2cab766b1ff657672b804e078656e0ce4067071140b0552d12ce3c01866231b212f3c65908b85aa"


recipe = LibSecp256k1RecipePinned()
