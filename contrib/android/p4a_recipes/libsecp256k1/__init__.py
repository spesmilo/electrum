from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "1ad5185cd42c0636104129fcc9f6a4bf9c67cc40"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "64080d7c3345fe8117787e328a09a3b493c38880cabf73d34e472ab0db4cb17ff989689f0c785680bdba39c446dc8a64d34587f4a0797b225c5687d0eb2da607"


recipe = LibSecp256k1RecipePinned()
