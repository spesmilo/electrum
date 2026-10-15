from pythonforandroid.recipes.sip import SipRecipe
from pythonforandroid.util import HashPinnedDependency

assert SipRecipe._version == "6.15.1"
assert SipRecipe.depends == ["python3", "packaging"], SipRecipe.depends
assert SipRecipe.python_depends == []


class SipRecipePinned(SipRecipe):
    sha512sum = "30a312419ba82c0221c0cf03c3fb3ad7d45bb8fe633d1d7477025a7986b0a7f7b7b781a8d9cd6bcdb78f3b872231fd1eed123a761b497861822f2e35093f574d"

    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
        HashPinnedDependency(package="setuptools-scm==8.3.1",
                             hashes=['sha256:332ca0d43791b818b841213e76b1971b7711a960761c5bea5fc5cdb5196fbce3']),
        HashPinnedDependency(package="packaging==26.0",  # pulled in by setuptools-scm
                             hashes=['sha256:b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529']),

    ]


recipe = SipRecipePinned()
