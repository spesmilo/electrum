from pythonforandroid.recipes.sip import SipRecipe


assert SipRecipe._version == "6.15.1"
assert SipRecipe.depends == ["setuptools", "packaging", "tomli", "python3"], SipRecipe.depends
assert SipRecipe.python_depends == []


class SipRecipePinned(SipRecipe):
    sha512sum = "30a312419ba82c0221c0cf03c3fb3ad7d45bb8fe633d1d7477025a7986b0a7f7b7b781a8d9cd6bcdb78f3b872231fd1eed123a761b497861822f2e35093f574d"


recipe = SipRecipePinned()
