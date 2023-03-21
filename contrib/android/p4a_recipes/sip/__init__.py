from pythonforandroid.recipes.sip import SipRecipe


assert SipRecipe._version == "6.7.7"
assert SipRecipe.depends == ["setuptools", "packaging", "toml", "ply", "python3"], SipRecipe.depends
assert SipRecipe.python_depends == []


class SipRecipePinned(SipRecipe):
    sha512sum = "b41a1e53e8bad1fca08eda2c89b8a7cabe6cb9e54d0ddeba0c718499b0288633fb6b90128d54f3df2420e20bb217d3df224750d30e865487d2b0a640fba82444"


recipe = SipRecipePinned()
