from pythonforandroid.recipes.hostqt6 import HostQt6Recipe


assert HostQt6Recipe._version == "6.10.2"
assert HostQt6Recipe.depends == []
assert HostQt6Recipe.python_depends == []


class HostQt6RecipePinned(HostQt6Recipe):
    # same source archive as qt6
    sha512sum = "bf1a1d42d57b4d2e77f7227f4cbe01e847fd65035461b89481063b32f25a57be6e5a07889acc4af65ca9ff9d27b7fe63bd2fe60b8aa7fa19d554394d799fbaa1"


recipe = HostQt6RecipePinned()
