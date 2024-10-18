from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "642c885b6102725e25623738529895a95addc4f4"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "81c0048630e4b2ab24a71fc2156ff9f15bc6d379106cbe4724acd18a48269d07df51660662bcea4df167578a43837a8bc27af380f3a37b4c69e30cdd72f2b3fb"


recipe = LibSecp256k1RecipePinned()
