from pythonforandroid.recipes.sip import SipRecipe


assert SipRecipe._version == "6.7.9"
assert SipRecipe.depends == ["setuptools", "packaging", "tomli", "ply", "python3"], SipRecipe.depends
assert SipRecipe.python_depends == []


class SipRecipePinned(SipRecipe):
    sha512sum = "bb9d0d0d92002b6fd33f7e8ebe8cd62456dacc16b5734b73760b1ba14fb9b1f2b9b6640b40196c6cf5f345e1afde48bdef39675c4d3480041771325d4cf3c233"


recipe = SipRecipePinned()
