from pythonforandroid.recipes.qt5 import Qt5Recipe


assert Qt5Recipe._version == "9b43a43ee96198674060c6b9591e515e2d27c28f"
assert Qt5Recipe.depends == ['python3']
assert Qt5Recipe.python_depends == []

recipe = Qt5Recipe()
