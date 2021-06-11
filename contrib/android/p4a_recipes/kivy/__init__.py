from pythonforandroid.recipes.kivy import KivyRecipe


assert KivyRecipe.depends == ['sdl2', 'pyjnius', 'setuptools', 'python3']
assert KivyRecipe.python_depends == ['certifi']


class KivyRecipePinned(KivyRecipe):
    # kivy master 2020-12-10 (2.0.0 plus a few bugfixes)
    version = "2debbc3b1484b14824112986cb03b1072a60fbfc"
    sha512sum = "6cabb77860e63059ab4b0663b87f6396fa9133839b42db754628fc9a55f10b8d759466110e0763fd8dac40a49a03af276cb93b05076471d12db796e679f33d1d"

    # mv "python_depends" into "depends" to ensure we can control what versions get installed
    depends = [*KivyRecipe.depends, *KivyRecipe.python_depends]
    python_depends = []


recipe = KivyRecipePinned()
