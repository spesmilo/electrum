from pythonforandroid.recipes.cryptography import CryptographyRecipe


assert CryptographyRecipe._version == "2.8"
assert CryptographyRecipe.depends == ['openssl', 'six', 'setuptools', 'cffi', 'python3']
assert CryptographyRecipe.python_depends == []


class CryptographyRecipePinned(CryptographyRecipe):
    sha512sum = "000816a5513691bfbb01c5c65d96fb3567a5ff25300da4b485e716b6d4dc789aec05ed0fe65df9c5e3e60127aa9110f04e646407db5b512f88882b0659f7123f"


recipe = CryptographyRecipePinned()
