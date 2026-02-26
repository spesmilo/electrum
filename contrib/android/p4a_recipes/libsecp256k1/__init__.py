from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "1a53f4961f337b4d166c25fce72ef0dc88806618"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "4072e45517bc1bb416250bc8e4fa4ed94f83b4eebbe25a70925fd7cc9759df3edbce64ab0116519c335f82353f6a029cde92018ed7116f2f85c8092a9adeb532"


recipe = LibSecp256k1RecipePinned()
