import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    # PYTHON_VERSION=    # < line here so that I can grep the codebase and teleport here
    version = "3.11.14"
    sha512sum = "4642f6d59c76c6e5dbd827fdb28694376a9cc76e513146d092b49afb41513b3c9dff2339cfcebfb5b260f5cdc49a59a69906e284e5d478b2189d3374e9e24fd5"

    # this property overrides the default hostpython dependencies for PyProjectRecipe recipies
    pyproject_base_dependencies = [
        HashPinnedDependency(package="build[virtualenv]==1.4.0",
                             hashes=['sha256:6a07c1b8eb6f2b311b96fcbdbce5dab5fe637ffda0fd83c9cac622e927501596']),
        HashPinnedDependency(package="pip==24.0",
                             hashes=['sha256:ba0d021a166865d2265246961bec0152ff124de910c5cc39f1156ce3fa7c69dc']),
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),

        # pin deptree build[virtualenv]==1.4.0
        HashPinnedDependency(package="packaging==26.0",
                             hashes=['sha256:b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529']),
        HashPinnedDependency(package="pyproject_hooks==1.2.0",
                             hashes=['sha256:9e5c6bfa8dcc30091c74b0cf803c81fdd29d94f01992a7707bc97babb1141913']),
        HashPinnedDependency(package="virtualenv==21.2.0",
                             hashes=['sha256:1bd755b504931164a5a496d217c014d098426cddc79363ad66ac78125f9d908f']),
        HashPinnedDependency(package="distlib==0.4.0",
                             hashes=['sha256:9659f7d87e46584a30b5780e43ac7a2143098441670ff0a49d5f9034c54a6c16']),
        HashPinnedDependency(package="filelock==3.25.2",
                             hashes=['sha256:ca8afb0da15f229774c9ad1b455ed96e85a81373065fb10446672f64444ddf70']),
        HashPinnedDependency(package="platformdirs==4.9.4",
                             hashes=['sha256:68a9a4619a666ea6439f2ff250c12a853cd1cbd5158d258bd824a7df6be2f868']),
        HashPinnedDependency(package="python_discovery==1.1.3",
                             hashes=['sha256:90e795f0121bc84572e737c9aa9966311b9fde44ffb88a5953b3ec9b31c6945e']),
    ]


recipe = HostPython3RecipePinned()
