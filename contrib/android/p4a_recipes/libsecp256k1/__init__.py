from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "dbd41db16a0e91b2566820898a3ab2d7dad4fe00"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "9012586149fb952309f0a1eb9f41dcd668f839eb38bfa9e942b53b1974b793dfe7616879766837f3d98d1523c826a49ead966bca35aee11d734c81a2f6fd9bf9"


recipe = LibSecp256k1RecipePinned()
