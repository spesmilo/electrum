import os

from pythonforandroid.recipes.hostpython3 import HostPython3Recipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert HostPython3Recipe.depends == []
assert HostPython3Recipe.python_depends == []
assert HostPython3Recipe.patches == []


class HostPython3RecipePinned(util.InheritedRecipeMixin, HostPython3Recipe):
    # PYTHON_VERSION=    # < line here so that I can grep the codebase and teleport here
    version = "3.14.7"
    sha512sum = "15254e8280a0188ad66df9b79f470784d505a08d415db8f8060e86a83ba3355f95618c550d01ce063b7b107dba9a860bf144fc80b4ed74f75b558cd08a08bb60"

    # use official releases from python.org that have sigs, instead of auto-generated archives from github
    url = 'https://www.python.org/ftp/python/{version}/Python-{version}.tgz'

    # this property overrides the default hostpython dependencies for PyProjectRecipe recipies
    pyproject_base_dependencies = [
        HashPinnedDependency(package="build==1.4.0",
                             hashes=['sha256:6a07c1b8eb6f2b311b96fcbdbce5dab5fe637ffda0fd83c9cac622e927501596']),
        HashPinnedDependency(package="pip==26.2.1",  # note: same version cpython 3.14.7 bundles
                             hashes=['sha256:71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e']),
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),

        # pin deptree build==1.4.0
        HashPinnedDependency(package="packaging==26.0",
                             hashes=['sha256:b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529']),
        HashPinnedDependency(package="pyproject_hooks==1.2.0",
                             hashes=['sha256:9e5c6bfa8dcc30091c74b0cf803c81fdd29d94f01992a7707bc97babb1141913']),
    ]


recipe = HostPython3RecipePinned()
