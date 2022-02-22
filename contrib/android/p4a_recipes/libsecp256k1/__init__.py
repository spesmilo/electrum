from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "1253a27756540d2ca526b2061d98d54868e9177c"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "92232cdefba54fce5573e8b4a542dcd307e56380e9b72841da00da1d1d48bfa6f4c0d157e5c294be5342e500237761376aee5e29adde70b2bf7be413cbd77571"


recipe = LibSecp256k1RecipePinned()
