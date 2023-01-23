from pythonforandroid.recipes.sip import SipRecipe


assert SipRecipe._version == "6.5.1"
assert SipRecipe.depends == ["setuptools", "packaging", "toml", "python3"]
assert SipRecipe.python_depends == []


class SipRecipePinned(SipRecipe):
    sha512sum = "2d6f225e653873462d97dfdc85bd308a26b66996e1bb98e2c3aa60a3b260db745021f1d3182db8e943fd216ee27a2f65731b96d287e94f8f2e7972c5df971c69"


recipe = SipRecipePinned()
