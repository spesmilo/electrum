from pythonforandroid.recipes.libsecp256k1 import LibSecp256k1Recipe


assert LibSecp256k1Recipe.depends == []
assert LibSecp256k1Recipe.python_depends == []


class LibSecp256k1RecipePinned(LibSecp256k1Recipe):
    version = "199d27cea32203b224b208627533c2e813cd3b21"
    url = "https://github.com/bitcoin-core/secp256k1/archive/{version}.zip"
    sha512sum = "879318ac0c0009cac94b23c25bba8e466638218aee59a085118f881b56201e7c47ad0bdcaf269168d1a82205df028a26288631c8cfb509d59b0bb71bb3261888"


recipe = LibSecp256k1RecipePinned()
