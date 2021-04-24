from pythonforandroid.recipes.setuptools import SetuptoolsRecipe


assert SetuptoolsRecipe._version == "51.3.3"
assert SetuptoolsRecipe.depends == ['python3']
assert SetuptoolsRecipe.python_depends == []


class SetuptoolsRecipePinned(SetuptoolsRecipe):
    sha512sum = "5a3572466a68c6f650111448ce3343f64c62044650bb8635edbff97e2bc7b216b8bbe3b4e3bccf34e6887f3bedc911b27ca5f9a515201cae49cf44fbacf03345"


recipe = SetuptoolsRecipePinned()
