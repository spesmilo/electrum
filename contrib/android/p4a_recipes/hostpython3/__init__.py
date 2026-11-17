import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []
assert HostPython3Recipe.patches == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    # PYTHON_VERSION=    # < line here so that I can grep the codebase and teleport here
    version = "3.11.18"
    sha512sum = "b4e532d6dfa59757facf684739bea7db320f25eb5df16d90acb132a1b62e00374b76a085ba5d42bdfec457e9db28fe1e32274627613cf745be29f4f7345ba140"

    # use official releases from python.org that have sigs, instead of auto-generated archives from github
    url = 'https://www.python.org/ftp/python/{version}/Python-{version}.tgz'

    # TODO: remove patch once CPython >= 3.12 is used (no more bundled setuptools)
    patches = [
        os.path.join(os.path.dirname(__file__), "patches", "cpython-311-ensurepip-no-setuptools.patch"),
    ]

    # this property overrides the default hostpython dependencies for PyProjectRecipe recipies
    pyproject_base_dependencies = [
        HashPinnedDependency(package="build==1.4.0",
                             hashes=['sha256:6a07c1b8eb6f2b311b96fcbdbce5dab5fe637ffda0fd83c9cac622e927501596']),
        HashPinnedDependency(package="pip==26.2.2",
                             hashes=['sha256:fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70']),
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),

        # pin deptree build==1.4.0
        HashPinnedDependency(package="packaging==26.0",
                             hashes=['sha256:b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529']),
        HashPinnedDependency(package="pyproject_hooks==1.2.0",
                             hashes=['sha256:9e5c6bfa8dcc30091c74b0cf803c81fdd29d94f01992a7707bc97babb1141913']),
    ]


recipe = HostPython3RecipePinned()
