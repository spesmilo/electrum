from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "34495e3ac28cee89d9ec5af1ea36659242e459b8d359be3b8cf5fb2b6d80cbaefcce79d9d08a01db3be3705ef3fbb5c34dcae94b303edca3d222d9b7555d76c6"


recipe = LibSecp256k1RecipePinned()
