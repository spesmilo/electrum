from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "0cdc758a56360bf58a851fe91085a327ec97685a"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "d8b133770db9badffba87a22eabb794ce99081429c61b1c8032eaed26039e514cfdae18f81ef1ea4a77f278477fd899dfcce2b772a011ae2ec5514c68b6e453a"


recipe = LibSecp256k1RecipePinned()
