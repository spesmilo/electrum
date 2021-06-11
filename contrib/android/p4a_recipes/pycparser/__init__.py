from pythonforandroid.recipes.pycparser import PycparserRecipe


assert PycparserRecipe._version == "2.14"
assert PycparserRecipe.depends == ['setuptools', 'python3']
assert PycparserRecipe.python_depends == []


class PycparserRecipePinned(PycparserRecipe):
    sha512sum = "d5b9ab434a8944898ac23a4f51189db77b02b993bf3e3ca018852b117fc0eb43e460b156beaa5c1d631ad71c81e1649113e9fff7e33506b1e7d4de24d8b464c6"


recipe = PycparserRecipePinned()
